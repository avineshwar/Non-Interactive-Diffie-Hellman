gcc -g -O2 -ansi -Wall -Wsign-compare -Wchar-subscripts -Werror -I. -I/usr/include/ -I/home/nicolosi/devel/libdcrypt/include/  -c skgu_pki.c
gcc -g -O2 -ansi -Wall -Wsign-compare -Wchar-subscripts -Werror -I. -I/usr/include/ -I/home/nicolosi/devel/libdcrypt/include/  -c skgu_cert.c
gcc -g -O2 -ansi -Wall -Wsign-compare -Wchar-subscripts -Werror -I. -I/usr/include/ -I/home/nicolosi/devel/libdcrypt/include/ -c skgu_misc.c
gcc -g -O2 -ansi -Wall -Wsign-compare -Wchar-subscripts -Werror -I. -I/usr/include/ -I/home/nicolosi/devel/libdcrypt/include/ -c pv_misc.c
gcc -g -O2 -ansi -Wall -Wsign-compare -Wchar-subscripts -Werror -o skgu_pki skgu_pki.o skgu_cert.o skgu_misc.o pv_misc.o -L. -L/usr/lib/  -L/home/nicolosi/devel/libdcrypt/lib/ -ldcrypt  -lgmp
gcc -g -O2 -ansi -Wall -Wsign-compare -Wchar-subscripts -Werror -I. -I/usr/include/ -I/home/nicolosi/devel/libdcrypt/include/  -c skgu_nidh.c
gcc -g -O2 -ansi -Wall -Wsign-compare -Wchar-subscripts -Werror -o skgu_nidh skgu_nidh.o skgu_cert.o skgu_misc.o pv_misc.o -L. -L/usr/lib/  -L/home/nicolosi/devel/libdcrypt/lib/ -ldcrypt  -lgmp