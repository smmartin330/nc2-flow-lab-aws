import jwt
import os
import datetime
import time
import hmac
import hashlib
import base64
import pytz
import uuid
import logging
import requests
import json
import ipaddress
from copy import deepcopy
from pathlib import Path
from tofupy import Tofu
from jinja2 import Template
from nc2_lab_vars import *


class nc2Cluster:
    def __init__(self):
        self.number = None
        self.name = None
        self.payload = {}
        self.response = None

        self.pc_subnet_cidr = ""
        self.pc_subnet_id = ""
        self.pc_vip = ""
        self.pc_ips = ""
        self.flow_subnet_cidr = ""
        self.flow_subnet_id = ""


class LabBuild:
    def __init__(self):
        # Enable logging
        # logging.basicConfig(
        #    level=logging.DEBUG,  # set log level to debug
        #    format="%(asctime)s - %(levelname)s - %(message)s",
        #    filename="api_interaction.log",  # Alternatively, write logs to the file if filename param is passed
        # )

        self.build_params = {
            "prefix": {
                "desc": "Name prefix",
                "help": "A string that will prepend all AWS objects and NC2 cluster names.",
                "type": "str",
                "default": "nc2-flow-lab",
                "val": "",
            },
            "region": {
                "desc": "AWS Region",
                "help": "The AWS Region to use. Ensure available quota or else builds will fail.",
                "type": "str",
                "default": "us-east-2",
                "val": "",
            },
            "az": {
                "desc": "AWS Availability Zone",
                "help": "The AWS Availability Zone to use. Ensure available quota or else builds will fail.",
                "type": "str",
                "default": "us-east-2b",
                "val": "",
            },
            "vpc_cidr": {
                "desc": "VPC Supernet (Minimum /20)",
                "help": "The supernet for the AWS VPC in CIDR format. A /20 is the minimum to account for Flow networks starting at the 10th /24 to match cluster numbering.",
                "type": "str",
                "default": "172.20.0.0/16",
                "val": "",
            },
            "cluster_count": {
                "desc": "Clusters needed",
                "help": "How many clusters to build.",
                "type": "int",
                "default": 2,
                "val": "",
            },
            "host_type": {
                "desc": "Host type",
                "help": "The AWS host type to deploy. Refer to https://portal.nutanix.com/page/documents/details?targetId=Nutanix-Clusters-AWS:aws-clusters-aws-xi-supported-regions-metals.html for availability by region. This script does not yet validate availability before deploying, so insufficient capacity will result in failure.",
                "type": "str",
                "default": "z1d.metal",
                "val": "",
            },
            "host_qty": {
                "desc": "Hosts per cluster",
                "help": "The number of hosts per cluster",
                "type": "int",
                "default": 1,
                "val": "",
            },
            "aos_version": {
                "desc": "AOS Version",
                "help": "The AOS Version to deploy.",
                "type": "str",
                "default": "7.3",
                "val": "",
            },
            "software_tier": {
                "desc": "NCI Software Tier ",
                "help": "The NCI software tier, either 'pro' or 'ultimate.'",
                "type": "str",
                "default": "ultimate",
                "val": "",
            },
            "pc_version": {
                "desc": "Prism Central Version",
                "help": "The Prism Central version to deploy. A new PC will be built for each cluster.",
                "type": "str",
                "default": "pc.7.3",
                "val": "",
            },
            "pc_size": {
                "desc": "Prism Central size",
                "help": "The Prism Central size to deploy.",
                "type": "str",
                "default": "small",
                "val": "",
            },
            "ssh_key": {
                "desc": "Host SSH Key",
                "help": "Provide an SSH key from AWS. The key must already be created. Ensure you have the private key.",
                "type": "str",
                "default": "martin-test",
                "val": "",
            },
            "access_ips": {
                "desc": "Access IPs",
                "help": "A list of public IPs in CIDR format, comma seperated. A network load balancer will be created to enable access to Prism Central via the provided public IPs.",
                "type": "list",
                "default": "192.146.155.8/32,192.146.155.9/32",
                "val": "",
            },
        }
        self.networks = {}
        self.aws_params = {
            "project_prefix": "",
            "vpc_region": "",
            "vpc_az": "",
            "vpc_cidr": "",
            "cluster_count": 0,
        }
        self.aws_objects = {}

    def gather_info(self):
        filename = input("File name for JSON input (Blank to provide manually)> ")
        if filename != "":
            params_file = open(filename, "r")
            self.build_params = json.loads(params_file.read())

            for param, info in self.build_params.items():
                if info["type"] == "int" and isinstance(info["val"], int) == False:
                    print(
                        f"ERROR: {info['name']} must be an integer. Correct the input file and try again."
                    )
                    quit()
                elif info["type"] == "list" and isinstance(info["val"], list) == False:
                    print(
                        f"ERROR: {info['name']} must be a list. Correct the input file and try again."
                    )
                    quit()
                elif info["type"] == "str" and isinstance(info["val"], str) == False:
                    print(
                        f"ERROR: {info['name']} must be a string. Correct the input file and try again."
                    )
                    quit()
            return
        else:
            params_file = open("build_params.json", "r")
            self.build_params = json.loads(params_file.read())

            print(
                "Provide required information. Enter ? for help. Default values, when available, will be shown. To accept default value, press enter."
            )
            for (
                param,
                info,
            ) in (
                self.build_params.items()
            ):  # Iterate through the build options to gather info
                this_val = ""  # set current response to empty
                while this_val == "":  # Loop until we have a response
                    print(info["desc"])  # Print the build option description
                    if info["default"] != None:  # if there is a default value
                        print(
                            f"Default: {info['default']}"
                        )  # show the current default value
                    this_val = input("> ")  # look for a response

                    if this_val == "?":  # if ?
                        this_val = ""  # blank the response
                        print(info["help"])  # print the option's help test
                    elif (
                        this_val == "" and info["default"] != ""
                    ):  # if the option is blank and there is a default
                        this_val = info["default"]  # set the response to the default
                    elif (
                        this_val == "" and info["default"] == None
                    ):  # if no default and no answer given
                        print(
                            "This option has no default value, and must be user-supplied."
                        )  # Print message and then loop
                        continue

                if info["type"] == "int":
                    try:
                        self.build_params[param]["val"] = int(this_val)
                    except:
                        print("Error: Provide an integer.")
                        response = ""
                elif info["type"] == "list":
                    try:
                        this_val = this_val.split(",")
                        for r in range(0, len(this_val)):
                            this_val[r] = this_val[r].strip()
                        self.build_params[param]["val"] = this_val
                    except:
                        print("Error: Please provide a comma-seperated list.")
                        this_val = ""
                else:
                    self.build_params[param]["val"] = this_val  # store the response

    def validate_info(self):
        if self.build_params["cluster_count"]["val"] == 0:
            print(
                """Cluster count of 0 provided. VPC networking will be built 
                  but no clusters will be created. No Flow subnets will be created.
                  If this is unintended, Ctrl-C to quit. Or else, press enter to contine."""
            )
            input()
        elif self.build_params["cluster_count"]["val"] < 0:
            print("""ERROR: Cannot build negative numbers of clusters...""")
            quit()
        elif self.build_params["cluster_count"]["val"] > 10:
            print(
                "ERROR: This script only supports building up to 10 clusters simultaneously."
            )
            quit()

        print("Validating VPC CIDR...")
        try:
            cidr_network = ipaddress.IPv4Network(self.build_params["vpc_cidr"]["val"])
            cidr_prefixlen = cidr_network.prefixlen
            if cidr_prefixlen > 20:
                print("ERROR: VPC CIDR prefix length must be at most /20. ")
                quit()
            self.networks["vpc"] = str(cidr_network)
            print(f"VPC CIDR: {self.networks['vpc']}")
        except Exception as e:
            print(f"ERROR: VPC CIDR invalid. Error: {e}")
            quit()

        try:
            cidr_subnets = list(cidr_network.subnets(new_prefix=24))
            self.networks["vpc_public"] = str(cidr_subnets[0])
            print(f"VPC Public Subnet: {self.networks['vpc_public']}")
            self.networks["cluster_management"] = str(cidr_subnets[1])
            print(
                f"VPC Metal/Cluster Mgmt Subnet: {self.networks['cluster_management']}"
            )

            for i in range(0, self.build_params["cluster_count"]["val"]):
                self.networks["prism_central_" + str(i)] = str(cidr_subnets[10 + i])
                print(
                    f"Cluster {i} Prism Central Subnet: {self.networks['prism_central_'+str(i)]}"
                )

            for i in range(0, self.build_params["cluster_count"]["val"]):
                self.networks["flow_network_" + str(i)] = str(cidr_subnets[20 + i])
                print(
                    f"Cluster {i} Flow Subnet: {self.networks['flow_network_'+str(i)]}"
                )
        except Exception as e:
            print(
                """ERROR: The provided VPC CIDR subnet is insufficient 
                  to proceed with the requested number of clusters.
                  /20: up to 7 clusters | /19: up to 22 clusters | /18: up to 62 clusters"""
            )

        print("Validating Management Access IPs")
        for ip in self.build_params["access_ips"]["val"]:
            try:
                ipaddress.IPv4Network(ip)
                print(f"{ip} is a valid IPv4 Network Address.")
            except Exception as e:
                print(f"ERROR: {ip} is not a valid IPv4 network address.")
                quit()

        pass

    def set_aws_params(self):
        # set the aws params from the build params and do input validation (to be added )
        self.aws_params["access_key"] = AWS_ACCESS_KEY_ID
        self.aws_params["access_secret"] = AWS_SECRET_ACCESS_KEY
        self.aws_params["token"] = AWS_SESSION_TOKEN
        # project prefix - should check for valid characters.
        self.aws_params["project_prefix"] = self.build_params["prefix"]["val"]
        # aws region - should check for valid region
        self.aws_params["vpc_region"] = self.build_params["region"]["val"]
        # aws az - should check for valid az
        self.aws_params["vpc_az"] = self.build_params["az"]["val"]
        # cluster count - Already validated
        self.aws_params["cluster_count"] = self.build_params["cluster_count"]["val"]
        # vpc cidr - Already validated
        self.aws_params["vpc_cidr"] = self.networks["vpc"]
        # vpc cidr - Already validated
        self.aws_params["access_ips"] = self.build_params["access_ips"]["val"]
        return

    def generate_aws_templates(self):
        """
        Generates opentofu/terraform files from aws_networking.tf.j2 in templates folder.
        """

        # make folder
        try:
            self.directory_name = self.aws_params["project_prefix"]
            os.mkdir(self.directory_name)
            print(f"Directory '{self.directory_name}' created successfully.")
        except FileExistsError:
            print(f"Directory '{self.directory_name}' already exists.")
        except PermissionError:
            print(f"Permission denied: Unable to create '{self.directory_name}'.")
        except Exception as e:
            print(f"An error occurred: {e}")

        try:
            aws_template_output = open(
                os.path.join(self.directory_name, "aws_networking.tf"), "w"
            )
            aws_template_file = open(
                os.path.join("templates", "aws_networking.tf.j2"), "r"
            )
            aws_template = Template(aws_template_file.read())
            aws_template_file.close()
            aws_template_output.write(aws_template.render(self.aws_params))
            aws_template_output.close()
        except Exception as e:
            print(f"Error generating aws_ne.tf from template: {e}")
            quit()

        return

    def build_aws_networking(self):
        """
        Builds AWS networking via OpenTofu using generated configuration in provided directory.

        """
        working_dir = Path(self.directory_name)
        tofu = Tofu(cwd=working_dir)
        self.init = tofu.init()
        self.plan_log, self.plan = tofu.plan()
        if not self.plan or self.plan.errored:
            print("OpenTofu plan failed")
            return False, self.plan_log
        try:
            self.apply_log = tofu.apply()
            return True, self.apply_log
        except Exception as e:
            print(f"OpenTofu plan failed to apply: {e}")
            return False, self.apply_log

    def get_aws_created_objects(self):
        """
        Reads the tfstate to get the created objects and their IDs.
        self.aws_objects = {
            "vpc_default_rt": "rtb-*",
            "nat_eip": "eipalloc-*",
            "igw": "igw-*",
            "nat_gw": "nat-*",
            "private_nat_route": "r-rtb-*",
            "public_internet_route": "r-rtb-*",
            "public_rt": "rtb-*",
            "public_rt_assoc": "rtbassoc-*",
            "private_flow_subnet_1": "subnet-*",
            "private_flow_subnet_2": "subnet-*",
            "private_metal_subnet": "subnet-*",
            "private_pc_subnet": "subnet-*",
            "public_subnet": "subnet-*",
            "vpc": "vpc-*",
        }
        """
        self.directory_name = "nc2-flow-lab"
        tfstate_file = open(os.path.join(self.directory_name, "terraform.tfstate"), "r")
        tfstate_json = json.load(tfstate_file)
        for resource in tfstate_json["resources"]:
            self.aws_objects[resource["name"]] = resource["instances"][0]["attributes"][
                "id"
            ]
        return

    def build_nc2_cluster_objects(self):
        self.nc2_cluster_base_payload = {
            "data": {
                "organization_id": NC2_ORGANIZATION_ID,
                "cloud_account_id": NC2_CLOUD_ACCOUNT_ID,
                "region": self.build_params["region"]["val"],
                "name": "",
                "aos_version": self.build_params["aos_version"]["val"],
                "license": "nci",
                "software_tier": self.build_params["software_tier"]["val"],
                "use_case": "general",
                "capacity": [
                    {
                        "host_type": self.build_params["host_type"]["val"],
                        "number_of_hosts": self.build_params["host_qty"]["val"],
                    }
                ],
                
                "host_access_ssh_key": self.build_params["ssh_key"]["val"],
                "network": {
                    "management_subnet": self.aws_objects["private_metal_subnet"],
                    "availability_zone": self.build_params["az"]["val"],
                    "fvn_config": {
                        "subnet_cidr": "",
                        "subnet_cloud_id": "",
                    },
                    "fvn_enabled": True,
                    "management_services_access_policy": {
                        "mode": "restricted",
                        "ip_addresses": self.build_params["access_ips"]["val"],
                    },
                    "mode": "existing",
                    "prism_element_access_policy": {
                        "mode": "restricted",
                        "ip_addresses": self.build_params["access_ips"]["val"],
                    },
                    "test_network_connectivity": True,
                    "vpc": self.aws_objects["vpc"],
                    "vpc_cidr": self.networks["vpc"],
                },
                "prism_central": {
                    "management_subnet": "",
                    "mode": "new",
                    "ntp_server_ip_list": [
                        "0.pool.ntp.org",
                        "1.pool.ntp.org",
                        "2.pool.ntp.org",
                    ],
                    "version": self.build_params["pc_version"]["val"],
                    "vm_size": self.build_params["pc_size"]["val"],
                },
            }
        }
        self.nc2_clusters = {}
        for c in range(0, self.build_params["cluster_count"]["val"]):
            this_cluster = nc2Cluster()
            this_cluster.name = self.build_params["prefix"]["val"] + "-" + str(c)
            this_cluster.number = c
            this_cluster.pc_subnet_cidr = self.networks["prism_central_" + str(c)]
            this_cluster.pc_subnet_id = self.aws_objects["private_pc_subnet_" + str(c)]
            this_cluster.flow_subnet_cidr = self.networks["flow_network_" + str(c)]
            this_cluster.flow_subnet_id = self.aws_objects[
                "private_flow_subnet_" + str(c)
            ]
            this_cluster.payload = deepcopy(self.nc2_cluster_base_payload)
            this_cluster.payload["data"]["name"] = (
                self.build_params["prefix"]["val"] + "-" + str(c)
            )
            this_cluster.payload["data"]["prism_central"]["management_subnet"] = (
                self.aws_objects["private_pc_subnet_" + str(c)]
            )
            this_cluster.payload["data"]["network"]["fvn_config"]["subnet_cidr"] = (
                self.networks["flow_network_" + str(c)]
            )
            this_cluster.payload["data"]["network"]["fvn_config"]["subnet_cloud_id"] = (
                self.aws_objects["private_flow_subnet_" + str(c)]
            )

            self.nc2_clusters[c] = this_cluster
            pass

    def create_nc2_jwt(self):
        """
        Create a JWT token using the provided API key and key ID.

        Returns:
            The JWT token and it's expiry if successful, None otherwise.
        """

        try:
            curr_time = datetime.datetime.now(datetime.UTC)
            payload = {
                "aud": NC2_MYNUTANIX_API_KEYS_URL,
                "iat": curr_time,
                "exp": curr_time
                + datetime.timedelta(
                    seconds=600
                ),  # Nutanix recommends a 5 minute expiry
                "iss": NC2_ISSUER,
                "metadata": {"reason": "NC2 AWS Cluster Quick Starter"},
                "context": {},
            }
            body = "{}".format(NC2_KEY_ID)
            signature = base64.b64encode(
                hmac.new(
                    bytes(NC2_API_KEY, "latin-1"),
                    bytes(body, "latin-1"),
                    digestmod=hashlib.sha512,
                ).digest()
            )
            token = jwt.encode(
                payload, signature, algorithm="HS512", headers={"kid": NC2_KEY_ID}
            )
            logging.debug("Token: {}".format(token))

            self.jwt_token, self.jwt_token_exp = token, payload["exp"]
            print(token)
            return token, payload["exp"]

        except Exception as e:
            logging.error(f"JWT generation failed: {str(e)}")
            return None, None

    def create_nc2_aws_clusters(self):
        try:
            headers = {
                "Authorization": f"Bearer {self.jwt_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

            for cluster, data in self.nc2_clusters.items():
                # Send a POST request to create the cluster
                response = requests.post(
                    NC2_BASE_URL + NC2_CREATE_AWS_CLUSTER_URL,
                    json=data.payload,
                    headers=headers,
                )

                if response.status_code == 202:
                    data.response = response.json()
                else:
                    raise Exception(
                        f"Cluster creation failed with status code {response.status_code}, error {response.text}"
                    )

        except Exception as e:
            raise Exception(f"Error creating cluster: {str(e)}")

    def get_nc2_built_clusters(self):
        try:
            headers = {
                "Authorization": f"Bearer {self.jwt_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

            params = {"active": "true", "name": self.build_params["prefix"]["val"]}
            response = requests.get(
                NC2_BASE_URL + NC2_LIST_CLUSTERS_URL, params=params, headers=headers
            )

            if response.status_code == 200:
                self.built_clusters = response.json()["data"]
            else:
                raise Exception(
                    f"Cluster list failed with status code {response.status_code}, error {response.text}"
                )

        except Exception as e:
            raise Exception(f"Error listing clusters: {str(e)}")

    def get_nc2_prism_centrals(self):
        try:
            headers = {
                "Authorization": f"Bearer {self.jwt_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

            # logging.debug(headers)
            params = {"availability_zone": self.build_params["az"]["val"]}
            response = requests.get(
                NC2_BASE_URL
                + "/cloud-accounts/"
                + NC2_CLOUD_ACCOUNT_ID
                + "/regions/"
                + self.build_params["region"]["val"]
                + "/prism-centrals",
                params=params,
                headers=headers,
            )

            if response.status_code == 200:
                self.prism_centrals = response.json()["data"]
                for pc in self.prism_centrals:
                    if pc["vpc"] == self.aws_objects["vpc"]:
                        for cluster, data in self.nc2_clusters.items():
                            if data.pc_subnet_id == pc["management_subnet"]:
                                data.pc_vip = pc["pc_virtual_ip"]
                                data.pc_ips = pc["vm_ips"]
                                print(f"{cluster} - {pc['pc_virtual_ip']}")
                                pass
            else:
                raise Exception(
                    f"Prism Central list failed with status code {response.status_code}, error {response.text}"
                )

        except Exception as e:
            raise Exception(f"Error listing Prism Centrals: {str(e)}")

    def generate_aws_nlb_config(self):

        nlb_template_output = open(
            os.path.join(self.directory_name, "aws_nlb.tf"), "w"
        )
        nlb_template_file = open(
            os.path.join("templates", "aws_nlb.tf.j2"), "r"
        )
        nlb_template = Template(nlb_template_file.read())
        nlb_template_file.close()
        
        for cluster, info in self.nc2_clusters.items():
            nlb_config = {
                "project_prefix": self.aws_params["project_prefix"],
                "cluster_name": info.name,
                "cluster_number" : info.number,
                "pc_vip": info.pc_vip,
                "pc_cidr": info.pc_subnet_cidr
                }
            nlb_template_output.write(nlb_template.render(nlb_config))
        
        nlb_template_output.close()
        return


def main():
    lab_build = LabBuild()
    # lab_build.gather_info()
    # lab_build.validate_info()
    # lab_build.set_aws_params()
    # lab_build.generate_aws_templates()
    # lab_build.build_aws_networking()
    # lab_build.get_aws_created_objects()
    # lab_build.build_nc2_cluster_objects()
    lab_build.create_nc2_jwt()
    # # lab_build.create_nc2_aws_clusters()
    # # lab_build.get_nc2_built_clusters()
    # lab_build.get_nc2_prism_centrals()
    # lab_build.generate_aws_nlb_config()


if __name__ == "__main__":
    main()
