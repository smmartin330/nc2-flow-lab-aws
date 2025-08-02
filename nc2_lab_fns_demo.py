import argparse
from vars import *
from classes import *

def main():
    ### Lab Generator for AWS 
    ### Flow Network Security Lab Prep
    
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
    args.directory = "temp-demo"
    args.json = "temp-demo.json"

    lab_build = LabBuild(args)

    lab_build.read_project_data()
    lab_build.validate_info()
    lab_build.get_nc2_jwt()
    lab_build.read_built_cluster_data()
    lab_build.fns_labs_prep()
    
    

if __name__ == "__main__":
    main()
