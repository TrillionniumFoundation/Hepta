#include <iostream>
#include <string>
#include <vector>
int main()
{
    std::vector<std::string> words{"HIA", "HOSTCXX"};
    std::cout << words[0] << ' ' << words[1] << '\n';
    return words.size() != 2;
}
