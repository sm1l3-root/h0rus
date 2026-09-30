from osdetect import OsDetection
import os 
import subprocess
import sys
import re

class IfLinux():

    

    def LinCommands():
        if OsDetection.detect() == "lin":
            
            
           
            def LinRun():
                return "linux commands"
            return LinRun()
        else:
            print ("error lin")
    

    LinCommands()
    