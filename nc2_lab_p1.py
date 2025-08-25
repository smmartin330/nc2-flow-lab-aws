import argparse
from vars import *
from classes import *

def main():
    ### Lab Generator for AWS 
    ### Phase 1: Build AWS Cloud Networking and Request NC2 Clusters
    
    parser = argparse.ArgumentParser(description=f"NC2 Lab Generator for AWS")
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

    # debug hard-coded vars
    args.directory = "test-lab"
    args.json = "test-lab.json"

    lab_build = LabBuild(args)

    if args.json:
        lab_build.read_params_from_file()
    else:
        lab_build.manual_params_input()
    lab_build.validate_info()
    lab_build.set_aws_params()
    lab_build.render_template(folder="cloud", template="aws_provider", values=lab_build.aws_params)
    lab_build.render_template(folder="cloud", template="aws_networking", values=lab_build.aws_params)
    lab_build.cloud_tofu_project(action="init")
    lab_build.cloud_tofu_project(action="plan")
    lab_build.cloud_tofu_project(action="apply")
    lab_build.cloud_tofu_project(action="get_aws_ids")
    lab_build.build_nc2_cluster_objects()
    lab_build.get_nc2_jwt()
    lab_build.create_nc2_clusters()
    lab_build.close_logfile()


if __name__ == "__main__":
    main()
