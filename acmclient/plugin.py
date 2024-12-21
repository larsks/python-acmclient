#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
#

import logging
import os

import osc_lib

LOG = logging.getLogger(__name__)

DEFAULT_BAREMETAL_API_VERSION = "1.72"
DEFAULT_ACMCLIENT_API_VERSION = "1"

# Required by the OSC plugin interface
API_NAME = "acmclient"
API_VERSION_OPTION = "os_acmclient_api_version"
API_VERSIONS = {"1": "acmclient.plugin"}


def make_client(instance):
    return ClientWrapper(instance)


# Required by the OSC plugin interface
def build_option_parser(parser):
    """Hook to add global options

    Called from openstackclient.shell.OpenStackShell.__init__()
    after the builtin parser has been initialized.  This is
    where a plugin can add global options such as an API version setting.

    :param argparse.ArgumentParser parser: The parser object that has been
        initialized by OpenStackShell.
    """
    if "OS_BAREMETAL_API_VERSION" not in os.environ:
        os.environ["OS_BAREMETAL_API_VERSION"] = DEFAULT_BAREMETAL_API_VERSION

    parser.add_argument(
        "--os-acmclient-api-version",
        metavar="<acmclient-api-version>",
        default=osc_lib.utils.env(
            "OS_ACMCLIENT_API_VERSION", default=DEFAULT_ACMCLIENT_API_VERSION
        ),
        help=f"ACM Client API version, default={DEFAULT_ACMCLIENT_API_VERSION} (Env: OS_ACMCLIENT_API_VERSION)",
    )
    return parser


class ClientWrapper(object):
    def __init__(self, instance):
        self._instance = instance
