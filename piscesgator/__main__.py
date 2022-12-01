from piscesgator import main

# Check to see if colorama is installed otherwise print a warning message.
try:
    import colorama
    from colorama import Fore, Style
    colorama.init()
        
# Otherwise let's just do vanilla output.
except ImportError:
    print('Warning: colorama is not installed. Please install.')

# Main Code
if __name__ == '__main__':
    exit(main())
   
