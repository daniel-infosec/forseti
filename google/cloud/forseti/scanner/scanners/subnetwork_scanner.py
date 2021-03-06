# Copyright 2018 The Forseti Security Authors. All rights reserved.
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

"""Scanner for the subnetwork rules engine."""

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import subnetwork_rules_engine as sre
from google.cloud.forseti.scanner.scanners import base_scanner
from google.cloud.forseti.common.gcp_type import resource_util


LOGGER = logger.get_logger(__name__)


class SubnetworkScanner(base_scanner.BaseScanner):
    """Scanner for subnetwork."""

    def __init__(self, global_configs, scanner_configs, service_config,
                 model_name, snapshot_timestamp, rules):
        """Initialization.

        Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            service_config (ServiceConfig): Forseti 2.0 service configs.
            model_name (str): name of the data model.
            snapshot_timestamp (str): Timestamp, formatted as YYYYMMDDTHHMMSSZ.
            rules (str): Fully-qualified path and filename of the rules file.
        """
        super(SubnetworkScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
            snapshot_timestamp,
            rules)
        self.rules_engine = sre.SubnetworkRulesEngine(
            rules_file_path=self.rules,
            snapshot_timestamp=self.snapshot_timestamp)
        self.rules_engine.build_rule_book(self.global_configs)

    @staticmethod
    def _flatten_violations(violations):
        """Flatten RuleViolations into a dict for each RuleViolation member.

        Args:
            violations (list): The RuleViolations to flatten.

        Yields:
            dict: Iterator of RuleViolations as a dict per member.
        """
        for violation in violations:
            yield {
                'resource_name': violation.resource_name,
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'full_name': violation.full_name,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'violation_data': violation.violation_data,
                'resource_data': violation.resource_data
            }

    def _output_results(self, all_violations):
        """Output results.

        Args:
            all_violations (list): All violations.
        """
        all_violations = self._flatten_violations(all_violations)
        self._output_results_to_db(all_violations)

    def _find_violations(self, subnetworks):
        """Find violations in the resources with subnetwork policies.

        Args:
            resources (list): Contains all supported resource in subnetwork.

        Returns:
            list: All violations.
        """
        LOGGER.info('Finding subnetwork violations...')
        all_violations = []

        for subnetwork in subnetworks:
            LOGGER.debug('%s', subnetwork)
            violations = self.rules_engine.find_violations(subnetwork)
            LOGGER.debug(violations)
            all_violations.extend(violations)

        return all_violations

    def _retrieve(self):
        """Retrieves the data for scanner.

        Returns:
            list: a list of Resources, with a type in
                SUPPORTED_RETENTION_RES_TYPES
        """
        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        subnetwork_res = []
        with scoped_session as session:
            for subnetwork_from_data_model in data_access.scanner_iter(session, 'subnetwork'):

                proj = project.Porject(
                    project_id=subnetwork_from_data_model.parent.name,
                    full_name=subnetwork_from_data_model.parent.full_name
                )
                subn = subnetwork.Subnetwork.from_json(
                    parent=proj,
                    json_string=subnetwork_from_data_model.data)
                subnetwork_res.append(subn)

        return subnetwork_res

    def run(self):
        """Run, he entry point for this scanner."""
        subnetwork_info = self._retrieve()
        all_violations = self._find_violations(subnetwork_info)
        self._output_results(all_violations)
