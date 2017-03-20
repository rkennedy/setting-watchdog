// ConsoleApplication1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <windows.h>


int main()
{
    MessageBoxA(NULL, "Hello, world!", "Message", 0);
    std::cout << "Hello, world!" << std::endl;
    return 0;
}