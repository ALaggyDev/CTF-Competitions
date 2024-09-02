#include <stdlib.h>
#include <stdio.h>

int main()
{
    uint a, b;
    scanf("%d %d", &a, &b);

    for (uint seed = 0; seed < 10000000; seed++)
    {
        srand(seed);

        uint password = rand();

        if (rand() != a)
            continue;
        if (rand() != b)
            continue;

        printf("%d\n", password);
        break;
    }
}