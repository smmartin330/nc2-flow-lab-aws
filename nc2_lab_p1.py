import argparse
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

    # debug hard-coded vars
    args.directory = "nc2-flow-lab"
    args.json = "nc2-flow-lab.json"

    lab_build = LabBuild(args)

    if args.json:
        lab_build.read_params_from_file()
    else:
        lab_build.manual_params_input()

    lab_build.validate_info()
    lab_build.set_aws_params()
    lab_build.render_template(folder="cloud", template="aws_provider", values=lab_build.aws_params)
    lab_build.render_template(folder="cloud", template="aws_networking", values=lab_build.aws_params)
    # lab_build.build_aws_networking()
    # lab_build.get_aws_created_objects()
    # lab_build.build_nc2_cluster_objects()
    # lab_build.create_nc2_jwt()
    # lab_build.request_nc2_aws_clusters()


if __name__ == "__main__":
    main()
