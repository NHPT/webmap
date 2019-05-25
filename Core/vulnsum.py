HIGH=0
MEDIUM=0
LOW=0
def addHigh():
    global HIGH
    HIGH+=1

def addMedium():
    global MEDIUM
    MEDIUM+=1

def addLow():
    global LOW
    LOW+=1

def vulnprint():
    global HIGH
    global MEDIUM
    global LOW
    print("\033[1;32;1mThe Vulnerabilities Sum is:"+str(HIGH+MEDIUM+LOW)+"\033[0m")
    print("\033[1;31;1mHigh Vulnerabilities "+str(HIGH)+"\033[0m")
    print("\033[1;33;1mMedium Vulnerabilities "+str(MEDIUM)+"\033[0m")
    print("\033[1;36;1mLow Vulnerabilities "+str(LOW)+"\033[0m")
