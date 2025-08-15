import argparse
from vars import *
from classes import *

def main():
    ### Lab Generator for AWS 
    ### Phase 2: Get NC2 Cluster Info and build AWS Load Balancing.

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
    args.directory = "csc-lab"
    args.json = "csc-lab.json"

    lab_build = LabBuild(args)

    lab_build.read_project_data()
    lab_build.validate_info()
    lab_build.get_nc2_jwt()
    lab_build.read_built_cluster_data()
    lab_build.generate_aws_nlb_config()
    lab_build.render_template(folder="cloud", template="aws_provider", values=lab_build.aws_params)
    lab_build.cloud_tofu_project(action="plan")
    lab_build.cloud_tofu_project(action="apply")
    lab_build.cloud_tofu_project(action="get_aws_ids")
    lab_build.get_cluster_access_url()
    lab_build.close_logfile()

    

if __name__ == "__main__":
    main()
