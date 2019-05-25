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
"""A Bucket Resource.

See: https://cloud.google.com/storage/docs/json_api/v1/
"""

import json

from google.cloud.forseti.common.gcp_type import resource


class SubnetworkLifecycleState(resource.LifecycleState):
    """Represents the Subnetwork's LifecycleState."""
    pass


class Subnetwork(resource.Resource):
    """Subnetwork resource."""

    RESOURCE_NAME_FMT = 'subnetworks/%s'

    def __init__(
            self,
            subnetwork_id,
            full_name=None,
            data=None,
            name=None,
            parent=None,
            ipCidrRange=None,
            enableFlowLogs=None,
            privateIpGoogleAccess=None
            region=None):
        """Initialize.

        Args:
            bucket_id (int): The bucket id.
            full_name (str): The full resource name and ancestry.
            data (str): Resource representation of the bucket.
            name (str): The bucket's unique GCP name, with the
                format "buckets/{id}".
            display_name (str): The bucket's display name.
            locations (List[str]): Locations this bucket resides in. If set,
                there should be exactly one element in the list.
            parent (Resource): The parent Resource.
            lifecycle_state (LifecycleState): The lifecycle state of the
                bucket.
        """
        super(Subnetwork, self).__init__(
            resource_id=bucket_id,
            resource_type=resource.ResourceType.BUCKET,
            name=name,
            display_name=display_name,
            parent=parent,
            ipCidrRange=ipCidrRange,
            enableFlowLogs=enableFlowLogs,
            privateIpGoogleAccess=privateIpGoogleAccess,
            region=region)
        self.full_name = full_name
        self.data = data

    @classmethod
    def from_json(cls, parent, json_string):
        """Create a bucket from a JSON string.

        Args:
            parent (Resource): resource this bucket belongs to.
            json_string(str): JSON string of a bucket GCP API response.

        Returns:
            Bucket: bucket resource.
        """
        subnetwork_dict = json.loads(json_string)

        subnetwork_id = subnetwork_dict['id']
        return cls(
            parent=parent,
            subnetwork_id=subnetwork_id,
            full_name='{}bucket/{}/'.format(parent.full_name, subnetwork_id),
            display_name=subnetwork_dict['name'],
            region=subnetwork_dict['region'],
            data=json_string,
