#include <iostream>

int main() {
    std::cout << "Welcome to the calculator app!\n\n";

    std::cout << "Enter the first number: ";
    int first_number;
    std::cin >> first_number;

    std::cout << "Enter the second number: ";
    int second_number;
    std::cin >> second_number;

    std::cout << "Enter an operator (+, -, *, /): ";
    char op;
    std::cin >> op;

    std::cout << "The result is: ";
    if (op == '+') {
        std::cout << first_number << " + " << second_number << " = " << first_number + second_number << '\n';
    } else if (op == '-') {
        std::cout << first_number << " - " << second_number << " = " << first_number - second_number << '\n';
    } else if (op == '*') {
        std::cout << first_number << " * " << second_number << " = " << first_number * second_number << '\n';
    } else if (op == '/') {
        std::cout << first_number << " / " << second_number << " = " << first_number / second_number << '\n';
    } else {
        std::cout << "(error)\n";
    }

    std::cout << "Goodbye!\n";
}