import boto3
import json

# Helper function to read a file
def read_file(file_path):
    contents = None
    # Read file into variable, we are doing this in python because it doesn't require you to escape quotes
    with open(file_path ,'r') as read_file:
        contents = read_file.read()
        read_file.close()
    return contents

# Helper functions to write content to a file
def write_file(content,file_path):
    # write content to file
    with open(file_path ,'w') as write_file:
        write_file.write(content)
        write_file.close()

# Function to request info from the user and to create a new SES HTML Template
def create_template(session):
    
     # Create a boto client for ses
    client = session.client(service_name='ses')

    # Get user input
    template_name = input("HTML Template Name : ")
    email_subject = input("Email Subject : ")
    email_text_part = input("Text  (Leave blank for None) : ")
    file_path = input("Local path for HTML Template : ")

    # Use boto to make Create Template call
    response = client.create_template(
    Template={
    'TemplateName': template_name,
    'SubjectPart': email_subject,
    'TextPart': email_text_part,
    'HtmlPart': read_file(file_path)
    }
    )

    # Print confirmation
    print("")
    print("Template Created")

# Function to delete a template specified by the user
def delete_template(session):

    # Create a boto client for ses
    client = session.client(service_name='ses')

    # Get user input
    template_name = input("Template Name : ")

    # Use boto to delete specifed template
    response = client.delete_template(
    TemplateName=template_name
    )

    # Print confirmation
    print("")
    print("Template Deleted")

# Function to list existing templates in the specified region
def list_templates(session):
    
    # Create a boto client for ses
    client = session.client(service_name='ses')

    # use boto get get a list of the existing templates
    ses_templates_list = client.list_templates()

    # Print existing templates
    print()
    print("HTML Templates in SES")
    print("-----------------------------------------")
    for template in ses_templates_list["TemplatesMetadata"]:
        print(template["Name"])
    print("")

# function to retrieve an existing template from SES
def get_existing_template(session):
     
    # Create a boto client for ses
    client = session.client(service_name='ses')

    # Get user input
    template_name = input("Template Name : ")
    template_output_path = input("Output Path : ")

    # Use boto to get the specified template and write the HTML template to the specified template
    response = client.get_template(
    TemplateName=template_name
    )
    
    # Write template to file
    write_file(response['Template']['HtmlPart'], template_output_path)

    # Print info about template to console
    print("")
    print("Template Name : " + response['Template']['TemplateName'])
    print("Subject Part : " + response['Template']['SubjectPart'])
    print("Text Part : " + response['Template']['TextPart'])
    print("HTML Part : File - " + template_output_path )
    print("")

    # Print confirmation 
    print("Download Complete")

# Function to update a specified template
def update_template(session):

    # Create a boto client for ses
    client = session.client(service_name='ses')

    # Get user input
    template_name = input("HTML Template Name : ")
    email_subject = input("Email Subject : ")
    email_text_part = input("Text (Leave blank for None) : ")
    file_path = input("Local path for HTML Template : ")
    
    # Use boto to update an existing template
    response = client.update_template(
    Template={
    'TemplateName': template_name,
    'SubjectPart': email_subject,
    'TextPart': email_text_part,
    'HtmlPart': read_file(file_path)
    }
    )

    # Print confirmation
    print("")
    print("Update complete")

# Helper function to determine if a profile name or region have been specfied and create the proper instance of a boto session
def create_boto_session(profile_name,region_name):
    
    # default session - Will use default profile and region
    session = boto3.session.Session()
    
    # check what's been provided and create the right instance of session
    if profile_name is not None and region_name is not None:
        session = boto3.session.Session(profile_name=profile_name, region_name = region_name)
    elif profile_name is None and region_name is not None:
        session = boto3.session.Session(region_name = region_name)
    elif profile_name is not None and region_name is None:
        session = boto3.session.Session(profile_name=profile_name)

    return session

# Prompt users with menu and options to allow them to interact with AWS SES HTML Templates
def main():
    
    # Default values
    region_name = None
    profile_name = None

    # Menu header - Printed only once
    print(" --------------------------------------------")
    print("|       AWS SES HTML Template Loader        |")
    print(" --------------------------------------------")

    # Loop until a user wishes to exit
    while(1==1):
        print("")
        print("------------ Config Info ---------------")
        if region_name is None:
            print("Region :")
        else:
            print("Region : " + region_name)
        if profile_name is None:
            print("Profile Name :")
        else:
            print("Profile Name : " + profile_name)
        print("")
        print("------------ Options ------------")
        print("1. Create new template")
        print("2. List existing templates")
        print("3. Get existing template")
        print("4. Update existing templates")
        print("5. Delete template")
        print("6. Change region")
        print("7. Change profile name")
        print("8. Exit")
        user_selection = input("What would you like to do? (1-8) : ")
        print("")

        # Create/recreate the session with each call, this is so that we ensures we won't miss the profile or region info if it's provided
        session = create_boto_session(profile_name,region_name)

        # Depending on user input preform the requested function
        if int(user_selection)  == 1:
            create_template(session)
        elif int(user_selection) == 2:
            list_templates(session)
        elif int(user_selection) == 3:
            get_existing_template(session)
        elif int(user_selection) == 4:
            update_template(session)
        elif int(user_selection) == 5:
            delete_template(session)
        elif int(user_selection) == 6 :
            region_name = input("Region : ")
        elif int(user_selection) == 7:
            profile_name = input("Profile name (Leave blank for default) : ")
        elif int(user_selection) == 8:
            exit()

if __name__ == "__main__": main()