print("hello good morning everyone")
print("this is a sample code for testing")
a = 10
b = 20
c = 30
print(a + b + c)
print("the sum of three values is:", a + b + c )
print("ATIF KHAN is the boss of cricket team")
print("KING OF NURABAD {DON OF NURABAD}")
# program to execute in python
print("Factorial to find a recursive solution:")
print("Recursion is a method of solving a problem where the solution depends on solutions to smaller instances of the same problem.")

def factorial(n):
    if n == 0:
        return 1
    else:
        return n * factorial(n - 1)

num = int(input("Enter a number to find its factorial: "))
result = factorial(num) 
print(f"The factorial of {num} is: {result}")


