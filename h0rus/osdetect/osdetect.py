import sys
class OsDetection():
    def detect():
        if sys.platform.startswith("win"):
            
            return "win"

        elif sys.platform.startswith("lin"):
            
            return "lin"
        
    #detect()