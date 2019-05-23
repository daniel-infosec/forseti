# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Rules engine for Subnetworks."""
import collections

from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import relationship
from google.cloud.forseti.scanner.audit import base_rules_engine
from google.cloud.forseti.scanner.audit import errors

LOGGER = logger.get_logger(__name__)


RuleViolation = collections.namedtuple(
    'RuleViolation',
    ['resource_id', 'resource_name', 'resource_type', 'full_name', 'rule_index',
     'rule_name', 'violation_type', 'resource_data']
)


class SubnetworkRulesEngine(base_rules_engine.BaseRulesEngine):
    """Rules engine for Subnetworks."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): snapshot timestamp. Defaults to None.
                If set, this will be the snapshot timestamp
                used in the engine.
        """
        super(SubnetworkRulesEngine, self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build SubnetworkRuleBook from the rules definition file.

        Args:
            global_configs (dict): Global configurations.
        """
        self.rule_book = SubnetworkRuleBook(self._load_rule_definitions())

    def find_violations(self, subnetworks, force_rebuild=False):
        """Determine whether subnetwork violate rules.

        Args:
            parent_resource (Resource): parent resource the subnetwork belongs to.
            subnetwork (List[subnetwork]): subnetwork to find violations for.
            force_rebuild (bool): If True, rebuilds the rule book. This will
                reload the rules definition file and add the rules to the book.

        Returns:
             generator: A generator of rule violations.
        """
        violations = itertools.chain()
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()
        resource_rules = self.rule_book.get_resource_rules()

        for rule in resource_rules:
            violations = itertools.chain(violations, rule.find_violations(subnetworks))

        return violations

    def add_rules(self, rule_defs):
        """Add rules to the rule book.

        Args:
            rule_defs (dict): rule definitions dictionary
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rule_defs)


class SubnetworkRuleBook(base_rules_engine.BaseRuleBook):
    """The RuleBook for Subnetwork resources."""

    def __init__(self, rule_defs=None):
        """Initialization.

        Args:
            rule_defs (dict): rule definitons dictionary.
        """
        super(SubnetworkRuleBook, self).__init__()
        self.resource_to_rules = collections.defaultdict(list)
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)

    def add_rules(self, rule_defs):
        """Add rules to the rule book.

        Args:
            rule_defs (dict): rule definitions dictionary.
        """
        for (i, rule) in enumerate(rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):
        """Add a rule to the rule book.

        Args:
            rule_def (dict): A dictionary containing rule definition
                properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.

        Example rule:
        # rules yaml:
          rules:
          - name: us-west1 is private google access and has flow logs enabled
            region: us-west1
            flow_logs: True
            private_google_access: True
          - name: us-central1 has flow logs enabled
            region: us-central1
            flow_logs: True

        ... gets parsed into
        {
            "rules": [
                {
                    "name": "us-west1 is private google access and has flow logs enabled",
                    "region": "us-west1",
                    "flow_logs": true,
                    "private_google_access": true
                },
                {
                    "name": "us-central1 has flow logs enabled",
                    "region": "us-central1",
                    "flow_logs": true
                }
            ]
        }
          
        """
        rule = Rule.from_config(rule_def)
        if rule.id in self.rules_map:
            raise DuplicateSubnetworkRuleError(
                'Rule id "%s" already in rules (rule %s)' % (
                    rule.id, rule_index))
        self.rule_indices[rule.id] = rule_index
        self.rules_map[rule.id] = rule

    def _build_rule(cls, rule_def, rule_index):
        """Build a rule.

        Args:
            rule_def (dict): A dictionary containing rule definition
                properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.

        Returns:
            Rule: rule for the given definition.
        """
        for field in ['name', 'restrictions']:
            if field not in rule_def:
                raise errors.InvalidRulesSchemaError(
                    'Missing field "{}" in rule {}'.format(field, rule_index))

        return Rule(name=rule_def.get('name'),
                    index=rule_index,
                    restrictions=rule_def.get('restrictions'))

    def find_violations(self, subnetworks):
        """Find subnetwork violations in the rule book.

        Args:
            subnetwork (List[Subnetwork]): The subnetworks to look for violations.

        Yields:
            RuleViolation: subnetwork rule violations.
        """

        all_restrictions = set()
        for subnetwork in subnetworks:
            for rule in self.rules:
                if subnetwork['region'] == rule['region']:
                    if rule['flow_logs']:
                        if not subnetwork['enableFlowLogs']:
                            yield self.RuleViolation(
                                    subnetwork=subnetwork,
                                    rule=rule,
                                    violation_type='FLOW_LOGS_NOT_ENABLED')
                    if rule['private_google_access']:
                        if not subnetwork['privateIpGoogleAccess']:
                            yield self.RuleViolation(
                                    subnetwork=subnetwork,
                                    rule=rule,
                                    violation_type='PRIVATE_IP_GOOGLE_ACCESS_NOT_ENABLED')
    RuleViolation = namedtuple('RuleViolation', ['subnetwork','rule','violation_type'])


class Rule(object):
    """Rule properties from the rule definition file.
       Also finds violations.
    """

    def __init__(self, name, index, restrictions):
        """Initialize.

        Args:
            name (str): Name of the loaded rule.
            index (int): The index of the rule from the rule definitions.
            restrictions (List[string]): The restrictions this rule enforces
              on subnetworks.
        """
        self.name = name
        self.index = index
        self.restrictions = restrictions

    def find_violations(self, resource, policy):
        """Find violations for this rule against the given resource.

        Args:
            parent_resource (Resource): The GCP resource associated with the
                subnetworks.
            restrictions (Iterable[str]): The restrictions to check.

        Yields:
            RuleViolation: subnetwork rule violation.
        """
        for restriction in self.restrictions:
            if restriction not in restrictions:
                yield RuleViolation(
                    resource_id=parent_resource.id,
                    resource_name=parent_resource.display_name,
                    resource_type=parent_resource.type,
                    full_name=parent_resource.full_name,
                    rule_index=self.index,
                    rule_name=self.name,
                    violation_type='SUBNETWORK_VIOLATION',
                    resource_data='',
                )
                return

