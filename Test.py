print("Hello World")
str = input("Please enter a string: ")
print("You entered:", str)
if len(str) > 0:
    print("The length of the string is:", len(str))
else:
    print("You entered an empty string.")

while True:
    choice = input("Do you want to enter another string? (yes/no): ")
    if choice.lower() == 'yes':
        str = input("Please enter a string: ")
        print("You entered:", str)
        if len(str) > 0:
            print("The length of the string is:", len(str))
        else:
            print("You entered an empty string.")
    elif choice.lower() == 'no':
        print("Goodbye!")
        break
    else:
        print("Invalid choice. Please enter 'yes' or 'no'.")