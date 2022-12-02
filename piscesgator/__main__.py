from piscesgator import main

# Check to see if colorama is installed otherwise print a warning message.
try:
    import colorama    
except ImportError:
    print('Warning: colorama is not installed. Please install.')
    print('pip install colorama')
    exit()

# Check to see if pandas is installed otherwise print a warning message.
try:
    import pandas
except ImportError:
    print('Warning: pandas is not installed. Please install.')
    print('pip install pandas')
    exit()

# Main Code
if __name__ == '__main__':
    exit(main())
   
