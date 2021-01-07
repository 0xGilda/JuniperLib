import JuniperPassword
import sys

if __name__ == '__main__':
    password = str(sys.argv[1])
    result = JuniperPassword.encrypt9(password)
    print result