import jwt
import os
import datetime
import time
import hmac
import hashlib
import base64
import pytz
import uuid
import requests
import json
import ipaddress
import argparse
from copy import deepcopy
from pathlib import Path
from tofupy import Tofu
from jinja2 import Template
from vars import *
from classes import *

def main():
    parser = argparse.ArgumentParser(description=f"NC2 Lab Generator")
    # parser.add_argument("--aws", "-a", help="Build on AWS", action='store_true') # only AWS for now, so that's the default
    # parser.add_argument("--azure", "-z", help="Build on Azure", action='store_true') # not yet!
    parser.add_argument(
        "--directory",
        "-d",
        help="Directory for lab build files, default is nc2-lab-YYYY-MM-DD",
    )
    parser.add_argument(
        "--json",
        "-j",
        help="Filename with build options. Use build_params.json as a template. ",
    )

    args = parser.parse_args()
    args.aws = True
    # Directory hard-coded for debug
    args.directory = "nc2-flow-lab"
    args.json = "nc2-flow-lab.json"

    lab_build = LabBuild(args)

    # lab_build.gather_info()
    # lab_build.validate_info()
    # lab_build.set_aws_params()
    # lab_build.render_template("aws_provider", lab_build.aws_params)
    # lab_build.render_template("aws_networking", lab_build.aws_params)
    # lab_build.build_aws_networking()
    # lab_build.get_aws_created_objects()
    # lab_build.build_nc2_cluster_objects()
    lab_build.create_nc2_jwt()
    cluster_id = lab_build.get_nc2_cluster_id_by_name()
    lab_build.get_nc2_cluster_by_id(id=cluster_id)
    # lab_build.request_nc2_aws_clusters()
    # lab_build.get_nc2_built_clusters()
    # lab_build.get_nc2_prism_centrals()
    # lab_build.generate_aws_nlb_config()


if __name__ == "__main__":
    main()
