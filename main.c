#include <stdio.h>
#include <stdlib.h>

///Criptare/Decriptare
void XORSHIFT32(unsigned int **R, int R0, int Length)
{ unsigned int r, i;
    r = R0;
    (*R) = (unsigned int *)malloc(Length * sizeof(unsigned int));
    for(i = 0; i < Length; i++)
    {
        r = r ^ r << 13;
        r = r ^ r >> 17;
        r = r ^ r << 5;
        (*R)[i] = r;
    }
}
void LiniarizareImagine(char *txt, unsigned int **L, int *j)
{unsigned int c;
  unsigned int i;
    FILE *f = fopen(txt, "rb");
    if(f == NULL)
    {
        printf("Nu s-a gasit imaginea cu numele %s!\n", txt);
        return;
    }
    (*L)= (unsigned int *)malloc(sizeof(unsigned int ));

    fseek(f, 54, SEEK_SET);

    while(fread(&c, 3, 1, f) == 1)
    {

        (*L) = (unsigned int *)realloc((*L), ((*j) + 1)*sizeof(unsigned int));
        (*L)[(*j)] = c;
        (*j)++;
    }


    fclose(f);
}

void SalvareImagine(char *imagine, unsigned int *L, unsigned int n)
{ unsigned int  i;
  unsigned char *header;
    FILE *f = fopen(imagine, "wb");


    if(f == NULL)
    {
      printf("Nu s-a putut deschide imaginea %s!\n", imagine);
      return;
    }

    fseek(f, 54, SEEK_SET);

   //printf("%u", n);
    for(i = 0; i < n; i++)
    {
        fwrite(&L[i], 3, 1, f);
    }
    fclose(f);

}
void PermutareAleatoare(unsigned int **perm, unsigned int *R, int Length)
{
     unsigned int k, r, aux;
    (*perm) = (unsigned int *)malloc(Length * sizeof(unsigned int));
    for(k = 0; k < Length; k++)
        (*perm)[k] = k;

    for(k = Length - 1; k  >= 1; k--)
    {

        r = R[Length - k - 1] % (k + 1);

        aux = (*perm)[r];
        (*perm)[r] = (*perm)[k];
        (*perm)[k] = aux;
    }

}
int Criptare(char *imagine, char *imagine_criptata, char *cheia_secreta)
{ unsigned int R0 = 0, SV = 0, *R, W, H, Length = 0, *perm;
  unsigned int *P, *P1;
  unsigned char *header;

     FILE *imag_initiala = fopen(imagine, "rb");
     FILE *imag_criptata = fopen(imagine_criptata, "wb");
     FILE *key = fopen(cheia_secreta, "r");
     if(imag_initiala == NULL)
     {
         printf("Nu s-a gasit imaginea cu numele %s!\n", imagine);
         return 0;
     }
     if(imag_criptata == NULL)
     {
         printf("NU");
         return;
     }
    if(key == NULL)
    {
        printf("Nu s-a introdus numele fisierului care contine cheia secreta!\n");
        return 0;
    }
    fscanf(key, "%u%u", &R0, &SV);
    fseek(imag_initiala, 18, SEEK_SET);
    fread(&W, sizeof(unsigned int), 1, imag_initiala);
    fread(&H, sizeof(unsigned int), 1, imag_initiala);

    LiniarizareImagine(imagine, &P, &Length);
    XORSHIFT32(&R, R0, 2 * W * H - 1);
    PermutareAleatoare(&perm, R, W*H);
    P1 = (unsigned int *)malloc(Length * sizeof(int));
    unsigned int i;
      //printf("%u  %u", W*H, Length);
      for(i = 0; i < Length; i++)
        P1[perm[i]] = P[i];




    P[0] = SV ^ P1[0] ^ R[W *H];
    for(i = 1; i < Length; i++)
        P[i] = P[i - 1]^P1[i]^R[W *H + i];

    free(perm);

    header = (unsigned char *)malloc(54 * sizeof(unsigned char));
    fseek(imag_initiala, 0, SEEK_SET);
    fseek(imag_criptata, 0, SEEK_SET);
    fread(header, 1, 54, imag_initiala);
    fwrite(header, 1, 54, imag_criptata);

   SalvareImagine(imagine_criptata, P, Length);

   fclose(imag_initiala);
   fclose(imag_criptata);
   fclose(key);
   free(R);
   free(P);
   free(P1);
    return 1;
}
int Decriptare(char *imagine_criptata, char *imagine_decriptata, char *cheia_secreta)
{
    unsigned int R0, SV, *R, W, H, Length = 0, i;
    unsigned int *perm, *perm1, *C, *D;
    unsigned char  *header;
    FILE *imag_initiala = fopen(imagine_criptata, "rb");
    FILE *imag_decriptata = fopen(imagine_decriptata, "wb");
    FILE *key = fopen(cheia_secreta, "r");

    if(imag_initiala == NULL)
    {
        printf("Nu s-a gasit imaginea criptata cu numele %s!\n", imagine_criptata);
        return 0;
    }
    if(key == NULL)
    {
        printf("Nu s-a gasit fisierul care contine cheia secreta(secret_key.txt) sau numele introdus este gresit!\n");
        return 0;
    }
    fscanf(key, "%u%u", &R0, &SV);

    fseek(imag_initiala, 18, SEEK_SET);
    fread(&W, sizeof(unsigned int), 1, imag_initiala);
    fread(&H, sizeof(unsigned int), 1, imag_initiala);

    LiniarizareImagine(imagine_criptata, &C, &Length);
    XORSHIFT32(&R, R0, 2 * W * H);
    PermutareAleatoare(&perm, R, Length);
    perm1 = (unsigned int *)malloc(Length * sizeof(int));
    for(i = 0; i < Length; i++)
        perm1[perm[i]] = i;

   free(perm);

    D = (unsigned int *)malloc(Length * sizeof(unsigned int));
    D[0] = SV ^ C[0] ^ R[W * H];
    for(i = 1; i < Length; i++)
        D[i] = C[i- 1] ^ C[i] ^ R[ W * H + i];

    for(i = 0; i < Length; i++)
        C[perm1[i]] = D[i];


   header = (unsigned char *)malloc(54 * sizeof(unsigned char));
    fseek(imag_initiala, 0, SEEK_SET);
    fseek(imag_decriptata, 0, SEEK_SET);
    fread(header, 1, 54, imag_initiala);
    fwrite(header, 1, 54, imag_decriptata);
    SalvareImagine(imagine_decriptata, C, Length);

    fclose(imag_initiala);
    fclose(imag_decriptata);
    fclose(key);
    free(R);
    free(C);
    free(D);
    free(perm1);

    return 1;

}
void Chi_Test(char *imagine)
{ unsigned char pixel[3];
  unsigned int i, W, H;
  unsigned int  *frecv_canalR, *frecv_canalG, *frecv_canalB, valR, valG, valB;
  float  frecv1, val1, val2, val3;
    FILE *f = fopen(imagine, "rb");
    if(f == NULL)
    {
        printf("Nu s-a gasit imaginea pentru care se cere testul!\n");
        return;
    }
    fseek(f, 18, SEEK_SET);
    fread(&W, sizeof(unsigned int), 1, f);
    fread(&H, sizeof(unsigned int), 1, f);
    fseek(f, 54, SEEK_SET);

    frecv_canalR = (unsigned int *)malloc(256 * sizeof(unsigned int));
    frecv_canalG = (unsigned int *)malloc(256 * sizeof(unsigned int));
    frecv_canalB = (unsigned int *)malloc(256 * sizeof(unsigned int));
    frecv1 = (W * H)/ (256 * 1.00);
    for(i = 0; i < 256; i++)
    {
        frecv_canalR[i] = 0;
        frecv_canalG[i] = 0;
        frecv_canalB[i] = 0;
    }

    while(fread(&pixel, 3, 1, f) == 1)
    {
        valB = pixel[0];
        valG = pixel[1];
        valR = pixel[2];
        frecv_canalB[valB]++;
        frecv_canalG[valG]++;
        frecv_canalR[valR]++;

    }

   val1 = val2 = val3 = 0;
   for(i = 0; i < 256; i++)
    {
        val1 += ((frecv_canalR[i] - frecv1)*(frecv_canalR[i] - frecv1)) / (frecv1 * 1.00);
        val2 += ((frecv_canalG[i] - frecv1) * (frecv_canalG[i] - frecv1)) / (frecv1 * 1.00);
        val3 += ((frecv_canalB[i] - frecv1) * (frecv_canalB[i] - frecv1)) / (frecv1 * 1.00);
    }

    printf("Testul chi-patrat pe canalele RGB pentru imaginea %s:\n", imagine);
    printf("R: %.2f\n", val1);
    printf("G: %.2f\n", val2);
    printf("B: %.2f\n", val3);



   free(frecv_canalR);
   free(frecv_canalG);
   free(frecv_canalB);
   fclose(f);
}
void Executa_Criptare()
{
    char *nume_imagine_initiala, *nume_imagine_criptata, *cheie, s[30];
   int k = 0;

         printf("Modulul de criptare...\n");


    printf("Introdu numele imaginii initiale:");  fgets(s, 30, stdin);
    nume_imagine_initiala = (unsigned char *)malloc(sizeof(unsigned char));
     for(k = 0; k  < strlen(s) - 1; k++)
    {
        nume_imagine_initiala = (unsigned char *)realloc(nume_imagine_initiala, (k + 1) * sizeof(unsigned char));
        nume_imagine_initiala[k] = s[k];

    }
    nume_imagine_initiala[k] = '\0';

    printf("Introdu numele pe care sa-l aiba imaginea criptata:");

    fgets(s, 30, stdin);
    nume_imagine_criptata = (unsigned char *)malloc(sizeof(unsigned char));
    for(k = 0; k  <strlen(s) - 1; k++)
    {
        nume_imagine_criptata = (unsigned char *)realloc(nume_imagine_criptata, (k + 1) * sizeof(unsigned char));
        nume_imagine_criptata[k] = s[k];

    }
    nume_imagine_criptata[k] = '\0';
    printf("Introdu numele fisierului care contine cheia secreta: ");
    fgets(s, 30, stdin);
    cheie = (unsigned char *)malloc(sizeof(unsigned char ));
    for(k = 0; k  < strlen(s) - 1; k++)
    {
        cheie = (unsigned char *)realloc(cheie, (k + 1) * sizeof(unsigned char));
        cheie[k] = s[k];

    }
    cheie[k] = '\0';
    printf("Se proceseaza...\n");
    Criptare(nume_imagine_initiala, nume_imagine_criptata, cheie);
    if(Criptare(nume_imagine_initiala, nume_imagine_criptata, cheie) == 1)
    printf("Criptare reusita! \n\n");

   free(nume_imagine_criptata);
   free(nume_imagine_initiala);
   free(cheie);
}
void Executa_Decriptare()
{
    char *nume_imagine_criptata, *nume_imagine_decriptata, *cheie, s[30];
   int k = 0;

         printf("Modulul de decriptare...\n");


    printf("Introdu numele imaginii criptate:");
    nume_imagine_criptata = (unsigned char *)malloc(sizeof(unsigned char));
        fgets(s, 30, stdin);
     for(k = 0; k  < strlen(s) - 1; k++)
    {
        nume_imagine_criptata = (unsigned char *)realloc(nume_imagine_criptata, (k + 1) * sizeof(unsigned char));
        nume_imagine_criptata[k] = s[k];

    }
    nume_imagine_criptata[k] = '\0';

    printf("Introdu numele pe care sa-l aiba imaginea decriptata:");

    fgets(s, 30, stdin);
    nume_imagine_decriptata = (unsigned char *)malloc(sizeof(unsigned char));
    for(k = 0; k  <strlen(s) - 1; k++)
    {
        nume_imagine_decriptata = (unsigned char *)realloc(nume_imagine_decriptata, (k + 1) * sizeof(unsigned char));
        nume_imagine_decriptata[k] = s[k];

    }
    nume_imagine_decriptata[k] = '\0';
    printf("Introdu numele fisierului care contine cheia secreta: ");
    fgets(s, 30, stdin);
    cheie = (unsigned char *)malloc(sizeof(unsigned char *));
    for(k = 0; k  < strlen(s) - 1; k++)
    {
        cheie = (unsigned char *)realloc(cheie, (k + 1) * sizeof(unsigned char));
        cheie[k] = s[k];

    }
    cheie[k] = '\0';
    printf("Se proceseaza...\n");
    Decriptare(nume_imagine_criptata, nume_imagine_decriptata, cheie);
    if(Decriptare(nume_imagine_criptata, nume_imagine_decriptata, cheie) == 1)
        printf("Decripatre reusita!\n\n");

  free(nume_imagine_criptata);
  free(nume_imagine_decriptata);
  free(cheie);
}


///Template Matching
typedef struct
{
    char nume[30];
} Sabloane;
void Grayscale(char *imagine_sursa)
{  unsigned char  pixel[3], c;
    unsigned int padding,W, H, aux, i, j;

    FILE *grayscale = fopen(imagine_sursa, "rb+");

    if(grayscale == NULL)
    {
        printf("Nu s-a gasit imaginea sursa (%s)!\n", imagine_sursa);
        return;
    }
    fseek(grayscale, 18, SEEK_SET);
    fread(&W, sizeof(W), 1, grayscale);
    fread(&H, sizeof(H), 1, grayscale);

    if(W % 4 != 0)
        padding = 4 - (3 * W) % 4;
    else padding = 0;

    fseek(grayscale, 54, SEEK_SET);

      for(i = 0; i  < H; i++)
      {
          for(j = 0; j < W; j++)
          {

              fread(pixel, 3, 1, grayscale);
              aux = 0.299*pixel[2] + 0.587*pixel[1] + 0.114*pixel[0];
              pixel[0] = pixel[1] = pixel[2] = aux;
              ///printf("%u %u %u\n", pixel[1], pixel[1], pixel[2]);
              fseek(grayscale, -3, SEEK_CUR);
              fwrite(pixel, 3, 1, grayscale);
              fflush(grayscale);
          }
          fseek(grayscale, padding, SEEK_CUR);
      }


        fclose(grayscale);
}
void Fereastra(unsigned int ***f, int x, int y, int H, int W, int **matrice)
{
    int i, j, fi, fj, a = 0, b = 0;
   unsigned char *canal_f;
    fi = x - (H/2);
    fj = y - (W/2);

    (*f) = (unsigned int **)malloc(H * sizeof(unsigned int *));
    for(i = 0; i <  H; i++)
        (*f)[i] = (unsigned int *)malloc(W * sizeof(unsigned int));

    for(i = fi; i < fi + H; i++)
    {
        b = 0;
        for(j = fj; j <  fj + W; j++)
        {
           canal_f = &matrice[i][j];
           (*f)[a][b] = (*canal_f);
           b++;
        }
        a++;

    }

}
float Calcul_Corelatie(int **s, int **f, int W, int H)
{  int i, j, n;
   double s_med = 0.00, f_med = 0.00, dev_standard_s = 0.00, dev_standard_f = 0.00;
   n = W * H;
   float corr = 0.00;


     ///calculez media valorilor intensitatii grayscale a sablonului
    for( i = 0; i < H; i++)
        for(j = 0; j < W; j++)
            s_med += s[i][j];
    s_med = s_med / (n * 1.00);

    ///calculez deviatia standard a valorilor intensitatii grayscale a pixelor in sablonul S
    for(i  = 0; i < H; i++)
        for(j = 0; j < W; j++)
           dev_standard_s += (s[i][j] - s_med) * (s[i][j] - s_med);
    dev_standard_s *= 1.00/(n - 1);
    dev_standard_s = sqrt(dev_standard_s);


    ///calculez media valorilor intensitatii grayscvale in fereastra f
    for(i = 0; i <  H; i++)
        for(j = 0; j <  W; j++)
              f_med += f[i][j];
    f_med *= 1/(n * 1.00);
    ///calculez deviatia standard a valorilor intensitatilor grayscale in fereastra f
    for(i = 0; i <  H; i++)
        for(j = 0; j < W; j++)
          dev_standard_f += (f[i][j] - f_med) *(f[i][j] - f_med);
    dev_standard_f *= 1.00/(n - 1);
    dev_standard_f = sqrt(dev_standard_f);

    ///calculez corelatia dintre sablonul S si fereastra f

    for(i = 0; i < H; i++)
        for(j = 0; j < W; j++)
            corr += (1.00 / (dev_standard_f * dev_standard_s))*(f[i][j] - f_med)*(s[i][j] - s_med);

      corr *= (1.00/n);

    return corr;
}
void Coloreaza_Contur(int x, int y, int W, int H, int ***matrice, unsigned int culoare)
{
    int i, j, fi, fj;
    fi = x - (H/2);
    fj = y - (W/2);
    for(j = fj; j < W + fj; j++)
        (*matrice)[fi][j] = culoare;

    for(j = fj; j < W + fj; j++)
        (*matrice)[fi + H - 1][j] = culoare;

    for(i  = fi; i <  fi + H; i++)
        (*matrice)[i][fj] = culoare;

    for(i = fi; i <  fi + H - 1; i++)
        (*matrice)[i][fj + W - 1] = culoare;
}
void Template_Matching(char *imagine, char *sabl, float prag_s, unsigned int culoare )
{ int n, W_imag, H_imag, W_sablon, H_sablon, x;
    int i, j, padding_imag, padding_sablon;
    unsigned int pixel, **s, **f;
    unsigned char *canal_s;

    FILE *imag = fopen(imagine, "rb+");
    FILE *sablon = fopen(sabl, "rb");
    if(imag == NULL)
    {
        printf("Nu s-a gasit imaginea %s apelata in functia Template_Matching!\n", imagine);
        return;
    }
    if(sablon == NULL)
    {
        printf("Nu s-a gasit sablonul %s\n", sabl);
        return;
    }
    fseek(imag, 18, SEEK_SET);
    fread(&W_imag, sizeof(W_imag), 1, imag);
    fread(&H_imag, sizeof(H_imag), 1, imag);
    fseek(imag, 54, SEEK_SET);

    fseek(sablon, 18, SEEK_SET);
    fread(&W_sablon, sizeof(W_sablon), 1, sablon);
    fread(&H_sablon, sizeof(H_sablon), 1, sablon);
    fseek(sablon, 54, SEEK_SET);

    n = W_sablon * H_sablon;
    if(W_imag % 4 != 0)
        padding_imag = 4 - (W_imag * 3) % 4;
    else padding_imag = 0;

    if(W_sablon % 4 != 0)
        padding_sablon = 4 - (W_sablon * 3) % 4;
    else padding_sablon = 0;


    ///creez matricea in care salvez pixelii imaginii
    unsigned int **matrice;
    matrice = (unsigned int **)malloc(H_imag * sizeof(unsigned int *));
    for(i = 0; i <  H_imag; i++)
        matrice[i] = (unsigned int *)malloc(W_imag * sizeof(unsigned int));

    for(i = 0; i  < H_imag; i++)
    {
        for(j  = 0; j < W_imag; j++)
        {
            fread(&pixel, 3, 1, imag);
            matrice[i][j] = pixel;
        }
        fseek(imag, padding_imag, SEEK_CUR);
    }

 ///creez o matrice care contine valorile intensitatii grayscale din sablonul S
    s = (unsigned int **)malloc(H_sablon * sizeof(unsigned int *));
    for(i = 0; i < H_sablon; i++)
        s[i] = (unsigned int *)malloc(W_sablon * sizeof(unsigned int));
     for(i = 0; i < H_sablon; i++)
     {
         for(j = 0; j < W_sablon; j++)
         {
             fread(&pixel, 3, 1, sablon);
             canal_s = &pixel;
             s[i][j] =  (*canal_s);

         }
         fseek(sablon, padding_sablon, SEEK_CUR);
     }




   for(i = 0; i < H_imag; i++)
   {
       for(j = 0; j < W_imag; j++)
       {
           if(i >= (H_sablon/2) && i + (H_sablon/2) < H_imag && j >= (W_sablon/2) && j + (W_sablon) < W_imag )
           {
               Fereastra(&f, i, j, H_sablon, W_sablon, matrice);
               if(Calcul_Corelatie(s, f, W_sablon, H_sablon) > prag_s)
               {


                  // printf("%.2f\n", Calcul_Corelatie(s, f, W_sablon, H_sablon) );
                   Coloreaza_Contur(i, j, W_sablon, H_sablon, &matrice, culoare);


               }
               for(x = 0; x < H_sablon; x++)
                free(f[x]);
               free(f);
           }
       }
   }
   for(i = 0; i < H_sablon; i++)
    free(s[i]);
   free(s);

    rewind(imag);
    fseek(imag, 54, SEEK_SET);
    for(i = 0; i <  H_imag; i++)
    {
        for(j = 0; j < W_imag; j++)
            fwrite(&matrice[i][j], 3, 1, imag);
        fseek(imag, padding_imag, SEEK_CUR);
    }
   fclose(imag);
   fclose(sablon);

}
void GenerareCulori(unsigned int **culori)
{ unsigned int culoare_curenta, k = 0;
  unsigned char *canal_culoare;


    (*culori) = (unsigned int *)malloc(10 * sizeof(unsigned int));
      ///generez culoarea rosu
      culoare_curenta = 0;
      canal_culoare = &culoare_curenta;
      canal_culoare += 2;
       *canal_culoare = 255;
       (*culori)[k++] = culoare_curenta;
       ///genrez culoarea galben
       culoare_curenta = 0;
       canal_culoare = &culoare_curenta;
       canal_culoare += 1;
       *canal_culoare = 255;
       canal_culoare += 1;
       *canal_culoare = 255;
      (*culori)[k++] = culoare_curenta;
       ///generez culoarea verde
        culoare_curenta = 0;
       canal_culoare = &culoare_curenta;
       canal_culoare += 1;
       *canal_culoare = 255;
      (*culori)[k++] = culoare_curenta;
       ///generez culoarea cyan
       culoare_curenta = 0;
       canal_culoare = &culoare_curenta;
       *canal_culoare = 255;
       canal_culoare += 1;
       *canal_culoare = 255;
       (*culori)[k++] = culoare_curenta;
       ///generez culoarea magenta
       culoare_curenta = 0;
       canal_culoare = &culoare_curenta;
       *canal_culoare = 255;
       canal_culoare += 2;
       *canal_culoare = 255;
      (*culori)[k++] = culoare_curenta;
       ///generez culoarea albastru
       culoare_curenta = 0;
       canal_culoare = &culoare_curenta;
       *canal_culoare = 255;
      (*culori)[k++] = culoare_curenta;
       ///genrez culoarea argintiu
       culoare_curenta = 0;
       canal_culoare = &culoare_curenta;
       *canal_culoare = 192;
       canal_culoare += 1;
       *canal_culoare = 192;
       canal_culoare += 1;
       *canal_culoare = 192;
      (*culori)[k++] = culoare_curenta;
       ///generez o nuanta de albastru
       culoare_curenta = 0;
       canal_culoare = &culoare_curenta;
       canal_culoare += 1;
       *canal_culoare = 140;
       canal_culoare += 1;
       *canal_culoare = 255;
      (*culori)[k++] = culoare_curenta;
      /// generez o nuanta de magenta
      culoare_curenta = 0;
       canal_culoare = &culoare_curenta;
       *canal_culoare = 128;
       canal_culoare += 2;
       *canal_culoare = 128;
       (*culori)[k++] = culoare_curenta;
       ///generez o alta nuanta de albaastru
       culoare_curenta = 0;
       canal_culoare = &culoare_curenta;
       canal_culoare += 1;
       *canal_culoare = 128;
       (*culori)[k] = culoare_curenta;

}

void Tablou_Sabloane(Sabloane **s, char *document_nume_sabloane)
{ int  i = 0, j = 0;
   char c[30];
   FILE *f = fopen(document_nume_sabloane, "r");
   if(f == NULL)
   {
       printf("Nu s-a gasit documentul %s text care contine numele sabloanelor!\n", document_nume_sabloane);
       return;
   }

    (*s)= (Sabloane *)malloc(sizeof(Sabloane));
   while(fscanf(f, "%s", &c) != EOF)
   {
        strcpy((*s)[i].nume, c);
        i++;
        (*s) = (Sabloane *) realloc((*s), (i + 1) * sizeof(Sabloane));
   }



   fclose(f);


}

void Duplicat(char *text)
{  char *header, c;
    FILE *f = fopen(text, "rb");
    if(f == NULL)
    {
        printf("Nu s-a gasit imaginea %s ceruta in functia Duplicat!\n", text);
        return;
    }



    FILE *duplicat = fopen("duplicat.bmp", "wb");
    if(duplicat == NULL)
    {
        printf("Nu se poate crea duplicat!\n");
        return;
    }
    header = (char *)malloc(54);
    fread(header, 1, 54, f);
    fwrite(header, 1, 54, duplicat);
    free(header);
    fseek(f, 54, SEEK_SET);
    fseek(duplicat, 54, SEEK_SET);

    while(fread(&c, sizeof(c), 1 , f) == 1)
        fwrite(&c, sizeof(c), 1, duplicat);


    fclose(f);
    fclose(duplicat);


}
int main()
{
     ///Ciptare/Decriptare/Chi-test
    unsigned char *nume_imagine_initiala, *nume_imagine_criptata, s1[30];
     int i;
    Executa_Criptare();
    Executa_Decriptare();

    printf("Introdu numele imaginii initiale pentru a se rula testul chi pentru aceasta:");
    fgets(s1, 30, stdin);
    nume_imagine_initiala = (unsigned char *)malloc(sizeof(unsigned char));
    for(i = 0; i < strlen(s1) - 1; i++)
    {

        nume_imagine_initiala = (unsigned char *)realloc(nume_imagine_initiala, (i + 1) * sizeof(unsigned char));
        nume_imagine_initiala[i] = s1[i];
    }
    nume_imagine_initiala[i] = '\0';
    printf("Introdu numele imaginii criptate pentru a se rula testul chi pentru aceasta:");
    fgets(s1, 30, stdin);
    nume_imagine_criptata = (unsigned char *)malloc(sizeof(unsigned char));
    for(i = 0; i < strlen(s1) - 1; i++)
    {
        nume_imagine_criptata = (unsigned char *)realloc(nume_imagine_criptata, (i + 1) * sizeof(unsigned char));
        nume_imagine_criptata[i] = s1[i];
    }
    nume_imagine_criptata[i] = '\0';
    Chi_Test(nume_imagine_initiala);
    Chi_Test(nume_imagine_criptata);

    free(nume_imagine_initiala);
    free(nume_imagine_criptata);


    ///TempalteMatching

    Sabloane *s;
    int  j, *culori, k = 0;
   float prag_s = 0.45;
   char *nume_imagine, *sablon;
    printf("Introdu numele imaginii pentru care sa se execute operatia de template matching:");
    fgets(s1, 30, stdin);
    nume_imagine = (unsigned char *)malloc(sizeof(unsigned char));
    for(i = 0; i < strlen(s1) - 1; i++)
    {
        nume_imagine = (unsigned char *)realloc(nume_imagine, (i + 1) * sizeof(unsigned char));
        nume_imagine[i] = s1[i];
    }
    nume_imagine[i] = '\0';

    printf("Introdu numele fisierului in care se afla numele celor 10 sabloane:");
    fgets(s1, 30, stdin);
    sablon = (unsigned char *)malloc(sizeof(unsigned char));
    for(i = 0; i < strlen(s1) - 1; i++)
    {
        sablon = (unsigned char *)realloc(sablon, (i + 1) * sizeof(unsigned char));
        sablon[i] = s1[i];
    }
    sablon[i] = '\0';
    Tablou_Sabloane(&s, sablon);
    GenerareCulori(&culori);

    for(i = 0; i < 10; i++)
        Grayscale(s[i].nume);

    printf("Se creeaza duplicat pentru imagiinea test.bmp cu numele duplicat.bmp.\n");

    Duplicat(nume_imagine);
    Grayscale("duplicat.bmp");
    printf("Se ruleaza algoritmul de template matching pe imaginea duplicat.bmp...\n");
    printf("Se proceseaza...\n");
   for(i = 0; i  <= 9; i++)
        Template_Matching("duplicat.bmp", s[i].nume, prag_s, culori[i]);


   for(i = 0; i < 10; i++)
    free(s[i].nume);

   free(s);
  free(nume_imagine);
  free(sablon);
    return 0;
}
