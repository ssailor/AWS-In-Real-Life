import os
import boto3
from datetime import datetime, timedelta, timezone
import base64
from dateutil import parser
import calendar
import json
import time

# Flag to only write warning and violation records, ignore writing good records
display_actionable_only = os.environ['display_actionable_only']

# HTML Table cells with coloring set depending on status
threshold_cell_good = '<td bgcolor="#4CA64C">Good</td>'
threshold_cell_warning = '<td bgcolor="#ffff4c">Warning</td>'
threshold_cell_violation = '<td bgcolor="#ff3232">Violation</td>'

# Pick up values from environment variables

# Rule Evaluation
# -------------------- #
# Good : Value < low_threshold
# Warning : Value > low_threshold and Value < high_threshold
# Violation : Value > high_threshold 

# Flag to run the rule that checks Active MFA on accounts
check_mfa = os.environ['check_mfa']

# Low threshold for Inactive users check
inactive_user_low = os.environ['inactive_user_low']

# High threshold for inactive users check
inactive_user_high = os.environ['inactive_user_high']

# Low threshold for password age check
password_age_low = os.environ['password_age_low']

# High threshold for password age check
password_age_high = os.environ['password_age_high']

# Low threshold for inactive key check
inactive_key_low = os.environ['inactive_key_low']

# High threshold for inactive key check
inactive_key_high = os.environ['inactive_key_high']

# Low threshold for key age check
key_age_low = os.environ['key_age_low']

# High threshold for key age check
key_age_high = os.environ['key_age_high']

# Model objects to parse file into 
class Password(object):
    def __init__(self):
        self.Enabled = None
        self.LastUsed = None
        self.LastChanged = None
        self.NextRotation = None
        self.ActiveMFA = None

class Key(object):
    def __init__(self):
        self.KeyID = None
        self.Active = None
        self.LastRotated = None
        self.LastUsed = None
        self.RegionLastUsed = None
        self.ServiceLastUsed = None

class Cert(object):
    def __init__(self):
        self.Active = None
        self.LastRotated = None

class User(object):
    def __init__(self):
        self.Username = None
        self.ARN = None
        self.UserCreation = None
        self.Password = None
        self.Keys = []
        self.Certs = []

# Conversion utility that attempts to parse the provided value as a datetime and if it's unable to it will provide a None value
# We do this because the file uses text such as N/A as values in date fields that don't apply to it
def ConvertToDateTime(item):
    rtn = None
    try:
        rtn = parser.parse(item)
    except:
        rtn = None
    return rtn

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

# Get the credentials report from IAM
def get_iam_credentials_report(session):
    
    # Create a boto client using IAM
    client = session.client(service_name='iam')

    # Generates a credentials report if one isn't already created (new reports can only be generated only every 4 hrs)
    client.generate_credential_report()

    # Pause 5 seconds to allow time for the report to be generated
    time.sleep(5)

    # Get the credentials report
    credentials_report = client.get_credential_report()

    # Decode credentials file into UTF-8
    content = credentials_report["Content"].decode('utf-8')

    # Return CSV Content of the Credentials file
    return content

# Get the password policies using boto 
def get_account_password_policies(session):
    
    # Create a client to access IAM services
    client = session.client(service_name='iam')

    # Get the account password policies
    password_policies = client.get_account_password_policy()

    # Return password policies
    return password_policies

# Parse the credentials file and load it into models
def parse_report_to_models(content):
    records = []
    # Collection of users parsed into models
    users = []

    # Flag to detect and skip the first row (header)
    header_row = True
    # Skip the root account record because this should be explicitly handled by account owner
    root_acount_record = True
    for item in content.split("\n"):
        # The first row is the header, skip it
        if header_row:
            header_row = False
        elif root_acount_record:
            root_acount_record = False
        else:
            records.append(item)

    for record in records:
        # split up each entry into it's column
        row_item = record.split(",")

        # Create and populate user
        current_user = User()
        current_user.Username = row_item[0]
        current_user.ARN = row_item[1]
        current_user.UserCreation = ConvertToDateTime(row_item[2])
        
        # Create and populate current users password
        current_user_password = Password()
        current_user_password.Enabled = row_item[3]
        current_user_password.LastUsed = ConvertToDateTime(row_item[4])
        current_user_password.LastChanged = ConvertToDateTime(row_item[5])
        current_user_password.NextRotation = ConvertToDateTime(row_item[6])
        current_user_password.ActiveMFA = row_item[7]
        current_user.Password = current_user_password

        # Create and populate current key 1
        current_user_key1 = Key()
        current_user_key1.KeyID = "Key1"
        current_user_key1.Active = row_item[8]
        current_user_key1.LastRotated = ConvertToDateTime(row_item[9])
        current_user_key1.LastUsed = ConvertToDateTime(row_item[10])
        current_user_key1.RegionLastUsed = row_item[11]
        current_user_key1.ServiceLastUsed = row_item[12]
        current_user.Keys.append(current_user_key1)

        # Create and populate current key 2
        current_user_key2 = Key()
        current_user_key2.KeyID = "Key2"
        current_user_key2.Active = row_item[13]
        current_user_key2.LastRotated = ConvertToDateTime(row_item[14])
        current_user_key2.LastUsed = ConvertToDateTime(row_item[15])
        current_user_key2.RegionLastUsed = row_item[16]
        current_user_key2.ServiceLastUsed = row_item[17]
        current_user.Keys.append(current_user_key2)

        # Create and populate current cert 1
        current_cert1 = Cert()
        current_cert1.Active = row_item[18]
        current_cert1.LastRotated = ConvertToDateTime(row_item[19])
        current_user.Certs.append(current_cert1)

        # Create and populate current cert 1
        current_cert2 = Cert()
        current_cert2.Active = row_item[20]
        current_cert2.LastRotated = ConvertToDateTime(row_item[21])
        current_user.Certs.append(current_cert2)

        # Add current user to Users list
        users.append(current_user)

    return users

# Calculate how many days have elapsesd since an event last occured
def get_days_since_event(value):
    if value is not None:
        return (datetime.now(timezone.utc).date() - value.date()).days

class Rules(object):
    
    def __init__(self, users):
        self.Users = users

    # Get today's date and format it for display on the report
    def get_today_date_formatted(self):
        current_date = datetime.today()
        output_date = calendar.month_name[current_date.month] + " " +  str(current_date.day) + " " +  str(current_date.year)
        return output_date

    # Generate formatted html rows to display in the access_levels table
    def generate_access_level_rows(self):

        temp_list = []

        # Loop through all users and collect the values for each required field
        for user in self.Users:
            # Populate formatted string with user values
            temp = '''<tr align="center">
                <td>''' + user.Username + '''</td>
                <td>'''+ str(user.Password.Enabled) +'''</td>
                <td>''' + str(user.Keys[0].Active) + '''</td>
                <td>''' + str(user.Keys[1].Active) + '''</td>
            </tr>
            '''
            # Add row to list 
            temp_list.append(temp)
        # Concat all rows into one string to drop into the template 
        return ''.join(temp_list)

    # Rule to check if users have MFA enabled on their accounts
    def generate_mfa_enabled_rows(self):
        
        # Check if flag is set to run this check, if not then table will be empty
        if check_mfa == True:
            
            temp_list =  []

            # Loop through each user and run their account agaisnt the thresholds. Generate a HTML row as output
            for user in self.Users:
                
                # Default Values
                status = 'good'
                threshold_cell = threshold_cell_good
                recommendation = "None"

                # Check if the user has MFA active on their account
                if user.Password.ActiveMFA == 'false':
                    status = 'violation'
                    threshold_cell = threshold_cell_violation
                    recommendation = "Enable MFA "
                
                # HTML Row Template - Populate with the value from the rule check
                temp = '''<tr align="center">
                    '''+ threshold_cell +'''
                    <td>'''+ user.Username +'''</td>
                    <td>'''+ recommendation +'''</td>
                </tr>
                '''

                # If user has display_actionable_only set to true then only write warning and violation records
                if display_actionable_only == True and status != 'good' or display_actionable_only == False :
                    # Add row to list 
                    temp_list.append(temp)

        # Concat all rows into one string to drop into the template 
        return ''.join(temp_list)

    # Rule to check for inactive users
    def generate_inactive_users_rows(self):
        
        temp_list =  []

        # Loop through each user and run their account agaisnt the thresholds. Generate a HTML row as output
        for user in self.Users:
            
            # Default Values
            status='good'
            threshold_cell = None
            recommendation = None

            # If user doesn't have console access, don't check password rules for them
            if user.Password.Enabled == 'false':
                continue
            
            days_since_last_used = 0
            # Check when / if the user has ever used their password
            if user.Password.LastUsed == None:
                days_since_last_used = get_days_since_event(user.UserCreation)
            else:
                days_since_last_used = get_days_since_event(user.Password.LastUsed)

            # Run audit for inactive users
            if days_since_last_used < inactive_user_low:
                status='good'
                threshold_cell = threshold_cell_good
                recommendation = "None"
            elif days_since_last_used >=  inactive_user_low and days_since_last_used <= inactive_user_high:
                status='warning'
                threshold_cell = threshold_cell_warning
                recommendation = "Determine if user requires console access"
            else:
                status='violation'
                threshold_cell = threshold_cell_violation
                recommendation = "Remove console access for this account"

            # Row template
            temp = '''<tr align="center">
                '''+ threshold_cell +'''
                <td>'''+ user.Username +'''</td>
                <td>'''+ recommendation +'''</td>
            </tr>'''

            # If user has display_actionable_only set to true then only write warning and violation records
            if display_actionable_only == True and status != 'good' or display_actionable_only == False :
                # Add row to list 
                temp_list.append(temp)

        # Concat all rows into one string to drop into the template 
        return ''.join(temp_list)

    # Generate rows to populate the password rotation table
    def generate_password_rotation_rows(self):
        
        temp_list =  []

        # Loop through each user and run their account agaisnt the thresholds. Generate a HTML row as output
        for user in self.Users:
            
            # Default Values
            status='good'
            threshold_cell = None
            recommendation = None
            days_since_last_changed = 0

            # If user doesn't have console access, don't check password rules for them
            if user.Password.Enabled == 'false':
                continue

            # Check when / if the user has ever used their password
            if user.Password.LastChanged == None:
                days_since_last_changed = get_days_since_event(user.UserCreation)
            else:
                days_since_last_changed = get_days_since_event(user.Password.LastChanged)

            # Run audit for inactive users
            if days_since_last_changed < password_age_low:
                status='good'
                threshold_cell = threshold_cell_good
                recommendation = "None"
            elif days_since_last_changed >=  password_age_low and days_since_last_changed <= password_age_high:
                status='warning'
                threshold_cell = threshold_cell_warning
                recommendation = "Recommend user to change password soon"
            else:
                status='violation'
                threshold_cell = threshold_cell_violation
                recommendation = "Prompt user to change password immediately"

            # Row template
            temp = '''<tr align="center">
                '''+ threshold_cell +'''
                <td>'''+ user.Username +'''</td>
                <td>'''+ recommendation +'''</td>
            </tr>'''

            # If user has display_actionable_only set to true then only write warning and violation records
            if display_actionable_only == True and status != 'good' or display_actionable_only == False :
                # Add row to list 
                temp_list.append(temp)

        # Concat all rows into one string to drop into the template 
        return ''.join(temp_list)

    # Rule to check for inactive keys on user accounts 
    def generate_inactive_keys_rows(self):
        
        temp_list =  []

        for user in self.Users:
            
            # Default Values
            status='good'
            threshold_cell = None
            recommendation = None

            # Loop through each key on a users account
            for key in user.Keys:
                
                # If key isn't active then don't run an audit on it
                if key.Active == 'false':
                    continue
                
                days_since_last_used = 0
                # Check when / if the user has ever used their password
                if key.LastUsed == None:
                    days_since_last_used = get_days_since_event(user.UserCreation)
                else:
                    days_since_last_used = get_days_since_event(key.LastUsed)

                # Run audit for inactive users
                if days_since_last_used < inactive_key_low:
                    status='good'
                    threshold_cell = threshold_cell_good
                    recommendation = "None"
                elif days_since_last_used >=  inactive_key_low and days_since_last_used <= inactive_key_high:
                    status='warning'
                    threshold_cell = threshold_cell_warning
                    recommendation = "Determine if key is needed"
                else:
                    status='violation'
                    threshold_cell = threshold_cell_violation
                    recommendation = "Inactivate key"

                # Row template
                temp = '''<tr align="center">
                    '''+ threshold_cell +'''
                    <td>'''+ user.Username +'''</td>
                    <td>'''+ key.KeyID +'''</td>
                    <td>'''+ recommendation +'''</td>
                </tr>'''

                # If user has display_actionable_only set to true then only write warning and violation records
                if display_actionable_only == True and status != 'good' or display_actionable_only == False :
                    # Add row to list 
                    temp_list.append(temp)

        # Concat all rows into one string to drop into the template 
        return ''.join(temp_list)

    # Rule to check when a users keys were last rotated
    def generate_key_rotation_rows(self):
        
        temp_list =  []

        # Loop through each user and run their account agaisnt the thresholds. Generate a HTML row as output
        for user in self.Users:
            
            # Default Values
            status='good'
            threshold_cell = None
            recommendation = None

            # Loop through each key on a users account
            for key in user.Keys:
                
                # If key isn't active then don't run an audit on it
                if key.Active == 'false':
                    continue
                
                days_since_last_rotated = 0
                # Check when / if the user has ever used their password
                if key.LastRotated == None:
                    days_since_last_rotated = get_days_since_event(user.UserCreation)
                else:
                    days_since_last_rotated = get_days_since_event(key.LastRotated)

                # Run audit for inactive users
                if days_since_last_rotated < key_age_low:
                    status = 'good'
                    threshold_cell = threshold_cell_good
                    recommendation = "None"
                elif days_since_last_rotated >=  key_age_low and days_since_last_rotated <= key_age_high:
                    status ='warning'
                    threshold_cell = threshold_cell_warning
                    recommendation = "Rotate key soon or determine if needed"
                else:
                    status='violation'
                    threshold_cell = threshold_cell_violation
                    recommendation = "Rotate or inactivate immediately"

                # Row template
                temp = '''<tr align="center">
                    '''+ threshold_cell +'''
                    <td>'''+ user.Username +'''</td>
                    <td>'''+ key.KeyID +'''</td>
                    <td>'''+ recommendation +'''</td>
                </tr>'''

                # If user has display_actionable_only set to true then only write warning and violation records
                if display_actionable_only == True and status != 'good' or display_actionable_only == False :
                    # Add row to list 
                    temp_list.append(temp)

        # Concat all rows into one string to drop into the template 
        return ''.join(temp_list)

class Email(object):

    def generate_template_data(self,session,rules):
        html_email_template_data = {}
        # Add date formatting for the report header to the template data 
        html_email_template_data['Date'] = rules.get_today_date_formatted()
        
        # Populate and add the Access Table content to the template data
        html_email_template_data['AccessTableRows'] = rules.generate_access_level_rows()

        # Populate and add Password Policies to the template data
        password_policies =  get_account_password_policies(session)
        html_email_template_data['password-policy-min-pass-length'] = password_policies["PasswordPolicy"]["MinimumPasswordLength"]
        html_email_template_data['password-policy-require-symbols'] = password_policies["PasswordPolicy"]["RequireSymbols"]
        html_email_template_data['password-policy-require-numbers'] = password_policies["PasswordPolicy"]["RequireNumbers"]
        html_email_template_data['password-policy-require-uppercase'] = password_policies["PasswordPolicy"]["RequireUppercaseCharacters"]
        html_email_template_data['password-policy-require-lowercase'] = password_policies["PasswordPolicy"]["RequireLowercaseCharacters"]
        html_email_template_data['password-policy-users-change-passwords'] = password_policies["PasswordPolicy"]["AllowUsersToChangePassword"]
        html_email_template_data['password-policy-expire-passwords'] = password_policies["PasswordPolicy"]["ExpirePasswords"]
        html_email_template_data['password-policy-password-age'] = password_policies["PasswordPolicy"]["MaxPasswordAge"]
        html_email_template_data['password-policy-password-reuse'] = password_policies["PasswordPolicy"]["PasswordReusePrevention"]
        html_email_template_data['password-policy-hard-expire'] = password_policies["PasswordPolicy"]["HardExpiry"]
        
        # Populate and add the Rules Threshold content to the template data
        # Check if we are checking for MFA and write proper content to the theshold table
        if check_mfa == True:
            html_email_template_data['MFAGood'] = "True"
            html_email_template_data['MFAViolation'] = "False"
        else:
            html_email_template_data['MFAGood'] = "-"
            html_email_template_data['MFAViolation'] = "-"

        html_email_template_data['InactiveUsersLow'] = inactive_user_low
        html_email_template_data['InactiveUsersHigh'] = inactive_user_high
        html_email_template_data['PasswordRotationLow'] = password_age_low
        html_email_template_data['PasswordRotationHigh'] = password_age_high
        html_email_template_data['InactiveKeysLow'] = inactive_key_low
        html_email_template_data['InactiveKeysHigh'] = inactive_key_high
        html_email_template_data['KeyRotationLow'] = key_age_low
        html_email_template_data['KeyRotationHigh'] = key_age_high

        # Run rules, generate content for rules tables. Add content to template data to push to HTML Template
        html_email_template_data['MFATableRows'] = rules.generate_mfa_enabled_rows()
        html_email_template_data['InactiveUsersTableRows'] = rules.generate_inactive_users_rows()
        html_email_template_data['PasswordRotationTableRows'] = rules.generate_password_rotation_rows()
        html_email_template_data['InactiveKeysTableRows'] = rules.generate_inactive_keys_rows()
        html_email_template_data['KeyRotationTableRows']= rules.generate_key_rotation_rows()

        return json.dumps(html_email_template_data)
    
    # Send data for the report generated from the program to the HTML Template, then SES will email out to desired recipents
    def send_templated_email_report(self,session,template_data):
        
        recipent_email_address=[os.environ['recipent_email_address']]
        ses_source_email = os.environ['ses_source_email']
        ses_template_name = os.environ['ses_template_name']
        
        # Create boto client for SES
        client = session.client(service_name='ses')

        # Send data to SES with the templated email service, this will will take this data, populate it into the HTML template and email it to recipents
        client.send_templated_email(
        Source= ses_source_email,
        Destination={
            'ToAddresses': recipent_email_address
        },
        Template=ses_template_name,
        TemplateData=template_data
        )

class main(object):
    
    profile_name = None
    region_name = os.environ["ses_region_name"]
    
    # Create a session for Boto3 based on what info in provided by for the profile_name and/or region_name
    session = create_boto_session(profile_name,region_name)

    # 1. Get Security File
    content = get_iam_credentials_report(session)

    # 2. Parse file into models
    users = parse_report_to_models(content)

    # 3. Check against rules
    rules = Rules(users)

    # 4 Send Templated Email
    email = Email()
    # Run the rules and generate the data that will be pushed to the template
    template_data = email.generate_template_data(session,rules)
    email.send_templated_email_report(session,template_data)
    
    print("Operation ran sucessfully")


if __name__ == "__main__": main()