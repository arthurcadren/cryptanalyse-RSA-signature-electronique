#include <conio.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

/*----------------- bibliothèques nécessaires pour les sockets :---------------------------------------*/
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <ws2tcpip.h>
#define PORT 8080
#define BUFSIZE 1024
/*----------------- bibliothèques nécessaires pour les sockets :---------------------------------------*/
void menu(void);
void quitter(void);
void erreur(void);
void menu_crypto(void);
void menu_calcul(void);
void pgcd(void);
void choix_calcul(void);
void modulo(void);
void p_e_e(void);
void primarite(void);
void choix_crypto(void);
void lecture(void);
void comparer(void);
unsigned long int crypt(unsigned char k, unsigned long int n, unsigned long int e);
unsigned char decrypt(unsigned long int k, unsigned long int d, unsigned long int n);
void crypter(void);
void decrypter(void);
void inscri(void);
int p_e_e2(int x);
void pgcd2(int a, int b, int* taille, int* tab[]);
void decomp(int*s, int*q, int*r, int*k);
int cle_priv(int e, int z);
void pq(int* p, int* q);
void decomposition(void);
unsigned long int sign(unsigned char hash, unsigned long int d, unsigned long int n);
unsigned char verify(unsigned long int signature, unsigned long int e, unsigned long int n);
unsigned char hash_message(char* message);

void main(void)
{
	printf("\n\n\n\n\n\n\n\n\t\t\t       CRYPTOGRAPHIE\n\n\n\n\n\n\n\n\n");
   printf("\n\n\t\t\t        version 1.0");
   getch();

   system("cls");

   menu();

   getch();
}

/******************************CRYPTANALYSE RSA *************************************/

void factorize(unsigned long int n, unsigned long int* p, unsigned long int* q) {
    unsigned long int i;
    for (i = 2; i <= sqrt(n); i++) {
        if (n % i == 0) {
            *p = i;
            *q = n / i;
            return;
        }
    }
    *p = n;
    *q = 1;
}

unsigned long int modInverse(unsigned long int e, unsigned long int phi) {
    unsigned long int t = 0, newt = 1;
    unsigned long int r = phi, newr = e;
    unsigned long int quotient, temp;

    while (newr != 0) {
        quotient = r / newr;
        temp = t;
        t = newt;
        newt = temp - quotient * newt;

        temp = r;
        r = newr;
        newr = temp - quotient * newr;
    }

    if (r > 1) return 0;  // e is not invertible
    if (t < 0) t = t + phi;
    return t;
}

void cryptanalyse(void) {
    unsigned long int n, e, p, q, phi, d;
    char nom_fichier[20], nom_fin[20];

    printf("\n\n\t\t\t    ********************\n");
    printf("\t\t\t      *CRYPTANALYSE RSA*\n");
    printf("\t\t\t    ********************\n\n\n\n");

    fflush(stdin);
    printf("Donner le nom du fichier à décrypter avec son extension : ");
    gets(nom_fichier);

    printf("\n\n\n\tdonner la clé publique n : ");
    scanf("%lu", &n);

    printf("\n\n\n\tdonner la clé publique e : ");
    scanf("%lu", &e);

    factorize(n, &p, &q);
    printf("\n\nLes facteurs trouvés sont p = %lu et q = %lu", p, q);

    phi = (p - 1) * (q - 1);
    d = modInverse(e, phi);

    if (d == 0) {
        printf("\n\nImpossible de trouver l'inverse modulaire.");
        return;
    }

    printf("\n\nLa clé privée est d = %lu", d);

    printf("\n\nDonner le nom du fichier de destination avec son extension : ");
    scanf("%s", nom_fin);

    FILE *source = fopen(nom_fichier, "rb");
    FILE *res_decrypt = fopen(nom_fin, "wb");

    if (source == NULL) {
        printf("Impossible d'ouvrir le fichier à décrypter.\n");
        return;
    }

    if (res_decrypt == NULL) {
        printf("Impossible d'ouvrir le fichier résultat.\n");
        fclose(source);
        return;
    }

    unsigned long int lect_int;
    unsigned char l;
    unsigned long int h = 0;

    printf("\n\n\t\tATTENDEZ SVP PENDANT LE DÉCRYPTAGE.");

    while ((feof(source) == 0) && (fread(&lect_int, sizeof(unsigned long int), 1, source) != 0)) {
        fseek(source, sizeof(unsigned long int) * h, SEEK_SET);
        fread(&lect_int, sizeof(unsigned long int), 1, source);
        l = decrypt(lect_int, d, n);
        fwrite(&l, sizeof(unsigned char), 1, res_decrypt);
        h++;
    }

    fclose(source);
    fclose(res_decrypt);

    printf("\n\n\n\n\n\n\n\n\n\nLe décryptage de votre fichier est terminé.");
    getch();
}


/******************************FIN CRYPTANALYSE RSA *************************************/

/*********************************SIGNATURE NUMERIQUE*******************************/

unsigned long int sign(unsigned char hash, unsigned long int d, unsigned long int n) {
    return crypt(hash, n, d);
}

unsigned char verify(unsigned long int signature, unsigned long int e, unsigned long int n) {
    return decrypt(signature, e, n);
}

unsigned char hash_message(char* message) {
    unsigned long int hash = 0;
    int c;

    while (c = *message++) {
        hash = c + (hash << 6) + (hash << 16) - hash;
    }

    return hash % 256; // Keep hash within the range of a single byte
}

/****************************MENU PRINCIPAL************************************/

void menu(void)
{
	int choix=0;

   printf("\n\n\t\t\t       ****************\n");
   printf("\t\t\t       *MENU PRINCIPAL*\n");
	printf("\t\t\t       ****************\n\n\n\n");
   printf("\t   TAPEZ :\n\n\n\n");
   printf("\t\t1\t   POUR\t        UTILISER LA CRYPTOGRAPHIE\n\n");
   printf("\t\t2\t   POUR\t        REALISER DIVERS CALCULS\n\n");
   printf("\t\t3\t   POUR\t        QUITTER LE LOGICIEL\n\n\n");
   printf("\t   CHOIX : ");
   scanf("%d",&choix);

   switch(choix)
   {
   	case 1 : system("cls");
      			menu_crypto();
      break;

      case 2 : system("cls");
      			menu_calcul();
      break;

      case 3 : quitter();
      break;

      default : erreur();
   }
}

/***************************MENU CRYPTOGRAPHIE*********************************/

void menu_crypto(void) {

    int choix = 0;

    printf("\n\n\t\t\t     ********************\n");
    printf("\t\t\t     *MENU CRYPTOGRAPHIE*\n");
    printf("\t\t\t     ********************\n\n\n\n");
    printf("\t   TAPEZ :\n\n\n\n");
    printf("\t\t1\t   POUR\t        VOUS INSCRIRE\n\n");
    printf("\t\t2\t   POUR\t        CRYPTER\n\n");
    printf("\t\t3\t   POUR\t        DECRYPTER\n\n");
    printf("\t\t4\t   POUR\t        SIGNER UN MESSAGE\n\n");
    printf("\t\t5\t   POUR\t        VERIFIER UNE SIGNATURE\n\n");
    printf("\t\t6\t   POUR\t        CRYPTANALYSE\n\n");
    printf("\t\t7\t   POUR\t        ENVOYER FICHIER CRYPTE\n\n");
    printf("\t\t8\t   POUR\t        MENU PRECEDENT\n\n\n");
    printf("\t   CHOIX : ");
    scanf("%d", &choix);

    switch (choix) {
        case 1: inscri(); break;
        case 2: system("cls"); crypter(); system("cls"); choix_crypto(); break;
        case 3: system("cls"); decrypter(); system("cls"); choix_crypto(); break;
        case 4: system("cls"); signer(); system("cls"); choix_crypto(); break;
        case 5: system("cls"); verifier(); system("cls"); choix_crypto(); break;
        case 6: system("cls"); cryptanalyse(); system("cls"); choix_crypto(); break;
        case 7: system("cls"); envoyer_fichier_crypte(); system("cls"); choix_crypto(); break;
        case 8: system("cls"); menu(); break;
        default: erreur();
    }
}

/*******************************SIGNATURE**************************************/

void signer(void) {
    char message[256];
    unsigned long int d, n;
    unsigned long int signature;
    unsigned char hash;

    printf("\n\n\t\t\t    *********\n");
    printf("\t\t\t      *SIGNER*\n");
    printf("\t\t\t      *********\n\n\n\n");

    fflush(stdin);
    printf("Entrez le message à signer : ");
    gets(message);

    printf("\n\n\n\tDonner votre clé privée n : ");
    scanf("%lu", &n);

    printf("\n\n\n\tDonner votre clé privée d : ");
    scanf("%lu", &d);

    hash = hash_message(message);
    signature = sign(hash, d, n);

    printf("\n\nSignature générée : %lu", signature);
    getch();
}

/*******************************VERIFICATION***********************************/

void verifier(void) {
    char message[256];
    unsigned long int e, n, signature;
    unsigned char hash;
    unsigned char verified_hash;

    printf("\n\n\t\t\t    *************\n");
    printf("\t\t\t      *VERIFIER*\n");
    printf("\t\t\t      *************\n\n\n\n");

    fflush(stdin);
    printf("Entrez le message à vérifier : ");
    gets(message);

    printf("Entrez la signature : ");
    scanf("%lu", &signature);

    printf("\n\n\n\tDonner la clé publique n : ");
    scanf("%lu", &n);

    printf("\n\n\n\tDonner la clé publique e : ");
    scanf("%lu", &e);

    hash = hash_message(message);
    verified_hash = verify(signature, e, n);

    if (hash == verified_hash) {
        printf("\n\nSignature vérifiée avec succès.");
    } else {
        printf("\n\nÉchec de la vérification de la signature.");
    }
    getch();
}

/*******************************CRYPTER****************************************/

void crypter(void) {
    FILE *source_crypt;
    FILE *res_crypt;

    unsigned char c;
    unsigned long int i = 0;
    unsigned long int k, n, e;
    char nom_fichier[20];

    printf("\n\n\t\t\t    *********\n");
    printf("\t\t\t      *CRYPTER*\n");
    printf("\t\t\t      *********\n\n\n\n");

    fflush(stdin);

    printf("Donner le nom du fichier source avec son extension : ");
    gets(nom_fichier);

    printf("\n\n\n\tdonner votre cle publique n : ");
    scanf("%lu", &n);

    printf("\n\n\n\tdonner votre cle publique e : ");
    scanf("%lu", &e);

    source_crypt = fopen(nom_fichier, "rb");
    if (source_crypt == NULL) {
        printf("Impossible d'ouvrir le fichier source.\n");
        return;
    }

    res_crypt = fopen("result.cry", "wb");
    if (res_crypt == NULL) {
        printf("Impossible d'ouvrir le fichier resultat.\n");
        fclose(source_crypt);
        return;
    }
    system("cls");
    printf("\n\n\t\tATTENDEZ SVP PENDANT LE CRYPTAGE.");

    while ((feof(source_crypt) == 0) && (fread(&c, sizeof(unsigned char), 1, source_crypt) != 0)) {
        fseek(source_crypt, sizeof(unsigned char) * i, SEEK_SET);
        fread(&c, sizeof(unsigned char), 1, source_crypt);
        k = crypt(c, n, e);
        fwrite(&k, sizeof(unsigned long int), 1, res_crypt);
        i = i + 1;
    }

    fclose(source_crypt);
    fclose(res_crypt);
    printf("\n\n\n\n\n\n\n\n\n\nLe cryptage de votre fichier est termine.");
    printf("\n\nvotre fichier crypter se nomme result.cry");
    getch();
}


/******************************FONCTION CRYPTAGE*******************************/

unsigned long int crypt(unsigned char k, unsigned long int n, unsigned long int e) {
    unsigned long int i, res = 1, nbre;

    if (k == ' ') {
        nbre = 26;  // espace correspond à 26
    } else {
        nbre = ((unsigned long int)(k - 'a'));  // a = 0, b = 1, ..., z = 25
    }

    for (i = 0; i < e; i++) {
        res = res * nbre;
        res = fmod(res, n);
    }

    return res;
}


/*******************************DECRYPTER**************************************/

void decrypter(void) {
    FILE *source;
    FILE *res_decrypt;
    char l;
    unsigned long int h = 0;
    unsigned long int d, n;
    unsigned long int lect_int;
    char nom_fichier[20], nom_fin[20];

    printf("\n\n\t\t\t    ***********\n");
    printf("\t\t\t      *DECRYPTER*\n");
    printf("\t\t\t        ***********\n\n\n\n");

    fflush(stdin);

    printf("Donner le nom du fichier avec son extension : ");
    gets(nom_fichier);

    printf("Donner le nom du fichier de destination avec son extension : ");
    gets(nom_fin);

    printf("\n\n\n\tdonner votre cle prive n : ");
    scanf("%lu", &n);

    printf("\n\n\n\tdonner votre cle prive d : ");
    scanf("%lu", &d);

    source = fopen(nom_fichier, "rb");
    if (source == NULL) {
        printf("Impossible d'ouvrir le fichier a decrypter.\n");
        erreur();
        return;
    }

    res_decrypt = fopen(nom_fin, "wb");
    if (res_decrypt == NULL) {
        printf("Impossible d'ouvrir le fichier resultat.\n");
        fclose(source);
        erreur();
        return;
    }
    system("cls");

    printf("\n\n\t\tATTENDEZ SVP PENDANT LE DECRYPTAGE.");

    while ((feof(source) == 0) && (fread(&lect_int, sizeof(unsigned long int), 1, source) != 0)) {
        fseek(source, sizeof(unsigned long int) * h, SEEK_SET);
        fread(&lect_int, sizeof(unsigned long int), 1, source);
        l = decrypt(lect_int, d, n);
        fwrite(&l, sizeof(unsigned char), 1, res_decrypt);
        h = h + 1;
    }

    fclose(source);
    fclose(res_decrypt);
    printf("\n\n\n\n\n\n\n\n\n\nLe decryptage de votre fichier est termine.");
    getch();
}


/****************************FONCTION DECRYPTAGE*******************************/

unsigned char decrypt(unsigned long int k, unsigned long int d, unsigned long int n) {
    unsigned long int i, res = 1;

    for (i = 0; i < d; i++) {
        res = res * k;
        res = fmod(res, n);
    }

    if (res == 26) {
        return ' ';  // espace
    } else {
        return ((unsigned char)(res + 'a'));  // 0 = a, 1 = b, ..., 25 = z
    }
}


/********************************LECTURE***************************************/

void lecture(void)
{
	int compteur_car;
   int compteur_ligne;
   int car_lect;
   FILE *fichier;
   char nom_fichier[20];

   printf("\n\n\t\t\t**********************\n");
   printf("\t\t\t*LECTURE D'UN FICHIER*\n");
	printf("\t\t\t**********************\n\n\n");
   fflush(stdin);
   printf("Donner le nom du fichier a lire (avec son extension) : ");
   gets(nom_fichier);

   fichier=fopen(nom_fichier,"r");

   if(fichier==NULL)
   {
   	printf("\n\nImpossible d'ouvrir le fichier a lire.\n");
   }

   compteur_ligne=0;
   compteur_car=0;
if(fichier!=NULL){
   printf("\n\nLecture du fichier en cours.\n\n");

   while((car_lect = fgetc(fichier))!=EOF)
   {
   	compteur_car = compteur_car + 1;
      printf("%c",car_lect);

      if(compteur_car == 40)
      {
      	compteur_car = 0;
         compteur_ligne = compteur_ligne + 1;
      }

      if(compteur_ligne>=17)
      {
      	compteur_car = 0;
         compteur_ligne = 0;
         getch();
         system("cls");
      }
   }
   printf("\n\n\nLa lecture du fichier est terminee.");
   }
   fclose(fichier);
   getch();

}

/*******************************COMPARAISON************************************/

void comparer(void)
{
	int compt=0;

   int car_lect,car_lect2;
   FILE *fichier;
   FILE *fichier2;
   char nom_fichier[20];
   char nom_fichier2[20];

   printf("\n\n\t\t\t  ***************************\n");
   printf("\t\t\t  *COMPARAISON DE 2 FICHIERS*\n");
	printf("\t\t\t  ***************************\n\n\n");

   fflush(stdin);

   printf("Donner le nom du fichier source (avec son extension) : ");
   gets(nom_fichier);

   printf("Donner le nom du fichier a comparer (avec son extension) : ");
   gets(nom_fichier2);

   fichier=fopen(nom_fichier,"r");

   fichier2=fopen(nom_fichier2,"r");

   if(fichier==NULL)
   {
   	printf("\n\nImpossible d'ouvrir le fichier source.\n");
   }

   if(fichier2==NULL)
   {
   	printf("\n\nImpossible d'ouvrir le fichier a comparer.\n");
   }

if((fichier!=NULL) && (fichier2!=NULL))
	{
   printf("\n\nLecture des fichiers en cours.\n\n");

   while(((car_lect = fgetc(fichier))!=EOF)&&((car_lect2 = fgetc(fichier2))!=EOF))
   {
   	if(car_lect!=car_lect2)
   	{
         compt=compt+1;
      }
   }

   if(compt==0)
	{
      printf("\n\nLes deux fichiers sont identiques.");
   }

   else
	{
      printf("\n\nIl y a %d caracteres d'ecart.",compt);
   }
   }
   fclose(fichier);
   fclose(fichier2);

  	getch();
}

/******************************CHOIX CRYPTO************************************/

void choix_crypto(void)
{
	int choix;

   printf("\n\n\n\n\t   QUE SOUHAITEZ VOUS FAIRE ?\n\n\n\n\n");
   printf("\t   TAPEZ :\n\n\n");
   printf("\t\t1\t   POUR\t        REVENIR AU MENU PRINCIPAL\n\n");
   printf("\t\t2\t   POUR\t        REVENIR AU MENU CRYPTOGRAPHIE\n\n");
   printf("\t\t3\t   POUR\t        QUITTER LE LOGICIEL\n\n\n");
   printf("\t   CHOIX : ");
   scanf("%d",&choix);

   switch(choix)
   {
   	case 1 : system("cls");
      			menu();
      break;

      case 2 : system("cls");
      			menu_crypto();
      break;

      case 3 : quitter();
      break;

      default : erreur();
   }
}



/******************************MENU CALCUL*************************************/

void menu_calcul(void)
{
 	int choix=0;

 	printf("\n\t\t\t     *************\n");
   printf("\t\t\t     *MENU CALCUL*\n");
	printf("\t\t\t     *************\n\n\n");
   printf("\t   TAPEZ :\n\n\n\n");
   printf("\t\t1\t   POUR\t       CALCULER LE PGCD DE 2 NOMBRES\n\n");
   printf("\t\t2\t   POUR\t       DECOMPOSER UN NOMBRE EN NOMBRES PREMIERS\n\n");
   printf("\t\t3\t   POUR\t       CALCULER UN MODULO\n\n");
   printf("\t\t4\t   POUR\t       TESTER LA PRIMARITE D'UN NOMBRE\n\n");
   printf("\t\t5\t   POUR\t       VOIR SI 2 NOMBRES SONT PREMIERS ENTRE EUX\n");
   printf("\t\t6\t   POUR\t       MENU PRECEDENT\n\n\n");
   printf("\t   CHOIX : ");
   scanf("%d",&choix);

   switch(choix)
   {
   	case 1 : system("cls");
      			pgcd();
               system("cls");
               choix_calcul();
      break;

      case 2 : system("cls");
      			decomposition();
               system("cls");
               choix_calcul();

      break;

      case 3 : system("cls");
      			modulo();
               system("cls");
               choix_calcul();
      break;

      case 4 : system("cls");
      			primarite();
               system("cls");
               choix_calcul();
      break;

      case 5 : system("cls");
      			p_e_e();
               system("cls");
               choix_calcul();
      break;

      case 6 : system("cls");
      			menu();
      break;

      default : erreur();
   }
}

/*********************************CALCUL DU PGCD*******************************/

void pgcd(void)
{
	int a,b,*reste,*s,*q;

   reste=(int*)malloc(sizeof(int));  //initialisation de reste
   s=(int*)malloc(sizeof(int));  //initialisation de s
   q=(int*)malloc(sizeof(int));  //initialisation de q

   printf("\n\n\t\t\t     ****************\n");
   printf("\t\t\t     *CALCUL DU PGCD*\n");
	printf("\t\t\t     ****************\n\n\n");
   printf("Donner le 1er entier : ");
   scanf("%d",&a);
   printf("\nDonner le 2eme entier : ");
   scanf("%d",&b);


    s=a;

    q=b;

    *reste=fmod(*s,*q);



   while(*reste!=0 && *reste>0)
   {


    s=*q;

    q=*reste;

    *reste=fmod(*s,*q);


   }
   printf("\nle PGCD de %d et %d est %d.",a,b,*q);
   getch();
}

/*********************************MODULO***************************************/

void modulo(void)
{
   int res,x,y;

   printf("\n\n\t\t\t    ******************\n");
   printf("\t\t\t    *CALCUL DU MODULO*\n");
	printf("\t\t\t    ******************\n\n\n");
   printf("\n\ncalcul de X modulo Y");
   printf("\n\nDonner X : ");
   scanf("%d",&x);

   printf("\n\nDonner Y : ");
   scanf("%d",&y);

   res=fmod(x,y);

   printf("\n\n%d modulo %d est egal a %d.",x,y,res);

   getch();
}

/*******************************PRIMARITE**************************************/

void primarite(void)
{
	int x,i,taille=0;

   printf("\n\n\t\t\t***********************\n");
   printf("\t\t\t*PRIMARITE D'UN NOMBRE*\n");
	printf("\t\t\t***********************\n\n\n");
   fflush(stdin);
   printf("Donner un entier : ");
   scanf("%d",&x);

   if(x==0 || x==1)
   {
   	printf("%d n'est pas premier.",x);
   }

   else
   {
   	for(i=2;i<x;i++)
   	{
      	if(x%i==0)
      	{
         	taille=taille+1;
      	}
   	}

   	if(taille==0)
   	{
   		printf("%d est premier.",x);
   	}

   	else
   	{
   		printf("%d n'est pas premier.",x);
   	}
   }
	getch();
}

/**************************PREMIERS ENTRE EUX**********************************/

void p_e_e(void)
{
	int a,b,*reste,*s,*q;

   reste=(int*)malloc(sizeof(int));  //initialisation de reste
   s=(int*)malloc(sizeof(int));  //initialisation de s
   q=(int*)malloc(sizeof(int));  //initialisation de q

   printf("\n\n\t\t\t   ********************\n");
   printf("\t\t\t   *PREMIERS ENTRE EUX*\n");
	printf("\t\t\t   ********************\n\n\n");
   printf("Donner le 1er entier : ");
   scanf("%d",&a);
   printf("\nDonner le 2eme entier : ");
   scanf("%d",&b);


    s=a;

    q=b;

    *reste=fmod(*s,*q);



   while(*reste!=0 && *reste>0)
   {


    s=*q;

    q=*reste;

    *reste=fmod(*s,*q);


   }

   if(*q==1)
   {
   	printf("\n\n%d et %d sont premiers entre eux.",a,b);
   }

   else
   {
   	printf("\n\n%d et %d ne sont pas premiers entre eux.",a,b);
   }

   getch();
}

/****************************CHOIX CALCUL**************************************/

void choix_calcul(void)
{
	int choix;

   printf("\n\n\n\n\t   QUE SOUHAITEZ VOUS FAIRE ?\n\n\n\n\n");
   printf("\t   TAPEZ :\n\n\n");
   printf("\t\t1\t   POUR\t        REVENIR AU MENU PRINCIPAL\n\n");
   printf("\t\t2\t   POUR\t        REVENIR AU MENU DES CALCULS\n\n");
   printf("\t\t3\t   POUR\t        QUITTER LE LOGICIEL\n\n\n");
   printf("\t   CHOIX : ");
   scanf("%d",&choix);

   switch(choix)
   {
   	case 1 : system("cls");
      			menu();
      break;

      case 2 : system("cls");
      			menu_calcul();
      break;

      case 3 : quitter();
      break;

      default : erreur();
   }
}

/********************************ERREUR****************************************/

void erreur(void)
{
	int choix;

	printf("\nERREUR DE SAISIE.");

   getch();
   system("cls");

   printf("\n\n\n\n\t\tSOUHAITEZ VOUS REVENIR AU MENU PRINCIPAL ?\n\n\n\n\n");
   printf("\t   TAPEZ :\n\n\n");
   printf("\t\t1\t   POUR\t        REVENIR AU MENU PRINCIPAL\n\n");
   printf("\t\t2\t   POUR\t        QUITTER LE LOGICIEL\n\n\n");
   printf("\t   CHOIX : ");
   scanf("%d",&choix);

   switch(choix)
   {
   	case 1 : system("cls");
      			menu();
      break;

      case 2 : quitter();
      break;

      default : erreur();
   }
}

/***********************************inscription********************************/

 void inscri(void)
{
   int p,q,e,z,d,n;
   system("cls");
      printf("\n\n\t\t\t\t*************\n");
   printf("\t\t\t\t*INSCRIPTION*\n");
	printf("\t\t\t\t*************\n\n\n");

	pq(&p,&q);
   n=p*q;
   z=(p-1)*(q-1);
   e=p_e_e2(z);
   printf("\n\n\n\n\n\n\n\n\t( n : %d ; e : %d ) est votre cle publique.",n,e);
   d=cle_priv(e,z);
   printf("\n\n\n\n\t( n : %d ; d : %d ) est votre cle privee.",n,d);
   getch();
   getch();
   getch();
   system("cls");
   choix_crypto();

}

/******************************************************************************/

int p_e_e2(int x)
{
	int y,*tab[100000],*taille,rep,i;
   taille=(int*)malloc(sizeof(int));


    taille=0;


   for(i=0;i<100000;i++)
   {
   	tab[i]=(int*)malloc(sizeof(int));
   }

   for(y=1;y<x;y++)
   {
   	pgcd2(x,y,taille,tab);
   }
   rand();
	rep=*tab[rand()%*taille];
   return rep;
}
/******************************************************************************/
void pgcd2(int a,int b,int* taille,int* tab[])
{
int *reste,*k,*s,*q;
reste=(int*)malloc(sizeof(int));
k=(int*)malloc(sizeof(int));
s=(int*)malloc(sizeof(int));
q=(int*)malloc(sizeof(int));

    s=a;
    q=b;
    reste=1;


decomp(s,q,reste,k);
while(*reste!=0&&*reste>0)
               {


    s=*q;

    q=*reste;


               decomp(s,q,reste,k);
               }
if(*q==1)
{


    tab[*taille]=b;

    taille=*taille+1;


}
}

/******************************************************************************/
void decomp(int*s,int*q,int*r,int*k)
{

    k=0;


while(*s>=*q)
           {


    s=*s-*q;

    k=*k+1;


           }

    r=*s;


}

/******************************************************************************/

int cle_priv(int e,int z)
{
	int d,i=0;

   while((e*i)%z!=1)
   {
   	i=i+1;
   }

   d=i;
   return d;
}
/******************************************************************************/

void pq(int* p,int* q)
{
int t[200],i,y,j,taille=0;

   for (i=3;i<200;i++)
   			{ y=0;
             for(j=2;j<i;j++)
             			{
                     if(i%j==0)
                     			{
                              y=y+1;
                              }
                     }
             if(y==0)
             			{
                     //printf("   %d   ",i);
                     t[taille]= i;
                     taille=taille+1;
                     }
            }
rand();

    p=t[rand()%taille];
    q=t[rand()%taille];



}

/*************************DECOMPOSITION****************************************/

void decomposition(void)
{
	int prem[100000],puissance[100000];
	int n,o,i,j,k,compt,taille=0;

   printf("\n\n\t\t     ***********************************\n");
   printf("\t\t     *DECOMPOSITION EN NOMBRES PREMIERS*\n");
	printf("\t\t     ***********************************\n\n\n");

   printf("\nDonner 1 entier : ");
	scanf("%d",&n);
   printf("\n\n");
   o=n;
   for(i=2;i<o+1;i++)
   {
    	compt=0;
      for(j=2;j<i;j++)
      {
        	if(i%j==0)
         {
           	compt=compt+1;
         }
      }

      if(compt==0)
      {
        	prem[taille]=i;
         taille=taille+1;
      }
   }

   for(i=0;i<taille;i++)
   {
   	k=0;
    	while(fmod(o,prem[i])==0)
      {
      	o=o/prem[i];
         k=k+1;
         puissance[i]=k;
      }
   }

   printf("%d =",n);

   for(i=0;i<taille;i++)
   {
    	if(puissance[i]!=0)
      {
      	printf(" (%d",prem[i]);
   		printf("^");
   		printf("%d)",puissance[i]);
      }
   }

   getch();
}

/******************************************************************************/

void quitter(void)
{
	system("cls");

   printf("\n\n\n\n\n\n\n\n\n");
   printf("       *     *   *	      ******   ****** *       * ****** * ******       \n");
   printf("      * *    *   *	      *    *   *       *     *  *    * * *    *       \n");
   printf("     *****   *   *            ******   ***      *   *   *    * * ******       \n");
   printf("    *     *  *   *	      *     *  *         * *    *    * * *     *      \n");
   printf("   *       * *****	      *      * ******     *     ****** * *      *     \n");

}

/*************************************END**************************************/


/*----------------- Initialisez et nettoyez la bibliothèque Winsock---------------------------------------*/

void init_winsock() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("Failed. Error Code : %d", WSAGetLastError());
        exit(EXIT_FAILURE);
    }
}

void cleanup_winsock() {
    WSACleanup();
}

void envoyer_fichier_crypte() {
    char nom_fichier[256];
    char ip_dest[16];
    unsigned short port = 8080;
    FILE *fichier;
    SOCKET sock;
    struct sockaddr_in server;
    char buffer[1024];
    int bytes_read;

    printf("\n\n\t\t\t    ********************\n");
    printf("\t\t\t    *ENVOYER FICHIER CRYPTE*\n");
    printf("\t\t\t    ********************\n\n\n");

    fflush(stdin);
    printf("Entrez le nom du fichier crypté avec son extension : ");
    gets(nom_fichier);

    printf("Entrez l'adresse IP de la machine destinataire : ");
    gets(ip_dest);

    fichier = fopen(nom_fichier, "rb");
    if (fichier == NULL) {
        printf("Impossible d'ouvrir le fichier.\n");
        return;
    }

    init_winsock();

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Could not create socket : %d", WSAGetLastError());
        cleanup_winsock();
        return;
    }

    server.sin_addr.s_addr = inet_addr(ip_dest);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("Connection error\n");
        closesocket(sock);
        cleanup_winsock();
        return;
    }

    printf("Connected to %s\n", ip_dest);

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fichier)) > 0) {
        if (send(sock, buffer, bytes_read, 0) < 0) {
            printf("Send failed\n");
            fclose(fichier);
            closesocket(sock);
            cleanup_winsock();
            return;
        }
    }

    printf("File sent successfully\n");

    fclose(fichier);
    closesocket(sock);
    cleanup_winsock();
}

/*----------------- Initialisez et nettoyez la bibliothèque Winsock---------------------------------------*/
