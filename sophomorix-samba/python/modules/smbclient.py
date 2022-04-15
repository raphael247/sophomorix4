#!/usr/bin/python3
print('Loading module sophomorix_smbclient.py ...')

import pprint

############################################################
def print_data(item,name='default_name'):
    """Übergabe mehrerer Daten"""
    print(f"{name} hat {len(name)} Buchstaben")
    print(f"{item} hat {len(item)} Buchstaben")
    return 0

############################################################
def greeting(users,username):
    """Übergabe EINER komplexen Datenstruktur"""
    #print(users) # overview of the data structure
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(users)
    print(f"{users['sAMAccountName'][username]['firstname']} is greeted in the morning with: {users['sAMAccountName'][username]['morning_greeting']}")
    print(f"{users['sAMAccountName'][username]['firstname']} is greeted in the evening with: {users['sAMAccountName'][username]['evening_greeting']}")
    print()


############################################################    
def distribute(config):
    """Distribute data from one user to (one or multiple) other user(s)

    config is a dictionary with the following keys:

    :scopy: True if data should be copied with server-site copy method
    :from_user: source user
    :from_path: sub dir in home of source user
    :to_users: list of target users
    :to_path: sub dir in home of target users
    """
    print()
    print("The following dictionary was received:")
    print(config)
    print()
    print(f"The resulting loop is:")
    
    for key, values in config.items():
        print('Key :: ', key)
        if(isinstance(values, list)):
            for value in values:
                source=config['from_user']+"/"+config['from_path']
                target=value+"/"+config['to_path']
                print(f" What to do:  copy  {source}  to  {target}")
    return 0


    

print('... module sophomorix_smbclient.py loaded')
