#include "skgu.h"

#define DEFAULT_LABEL "skgu_key"

struct rawpub {
  mpz_t p;			/* Prime */
  mpz_t q;			/* Order */
  mpz_t g;			/* Element of given order */
  mpz_t y;			/* g^x mod p */
};
typedef struct rawpub rawpub;

struct rawpriv {
  mpz_t p;			/* Prime */
  mpz_t q;			/* Order */
  mpz_t g;			/* Element of given order */
  mpz_t x;			/* x mod q */
};
typedef struct rawpriv rawpriv;

int 
get_rawpub (rawpub *rpub_ptr, dckey *pub) {
  const char *pub_as_str = (const char *) dcexport (pub);

  if (skip_str (&pub_as_str, ELGAMAL_STR)
      || skip_str (&pub_as_str, ":Pub,p="))
    return -1;

  mpz_init (rpub_ptr->p);
  mpz_init (rpub_ptr->q);
  mpz_init (rpub_ptr->g);
  mpz_init (rpub_ptr->y);

  if (read_mpz (&pub_as_str, rpub_ptr->p)
      || skip_str (&pub_as_str, ",q=")
      || read_mpz (&pub_as_str, rpub_ptr->q)
      || skip_str (&pub_as_str, ",g=")
      || read_mpz (&pub_as_str, rpub_ptr->g)
      || skip_str (&pub_as_str, ",y=")
      || read_mpz (&pub_as_str, rpub_ptr->y)) {
    return -1;
  }

  return 0;
}

int 
get_rawpriv (rawpriv *rpriv_ptr, dckey *priv) {
  const char *priv_as_str = (const char *) dcexport (priv);

  if (skip_str (&priv_as_str, ELGAMAL_STR)
      || skip_str (&priv_as_str, ":Priv,p="))
    return -1;

  mpz_init (rpriv_ptr->p);
  mpz_init (rpriv_ptr->q);
  mpz_init (rpriv_ptr->g);
  mpz_init (rpriv_ptr->x);

  if (read_mpz (&priv_as_str, rpriv_ptr->p)
      || skip_str (&priv_as_str, ",q=")
      || read_mpz (&priv_as_str, rpriv_ptr->q)
      || skip_str (&priv_as_str, ",g=")
      || read_mpz (&priv_as_str, rpriv_ptr->g)
      || skip_str (&priv_as_str, ",x=")
      || read_mpz (&priv_as_str, rpriv_ptr->x)) {
    return -1;
  }

  return 0;
}

void 
usage (const char *pname, int argcount)
{
  printf("argc count is: %d\n", argcount);
  printf ("Simple Shared-Key Generation Utility\n");
  printf ("Usage: %s PRIV-FILE PRIV-CERT PRIV-ID PUB-FILE PUB-CERT PUB-ID [LABEL]\n", pname);
  exit (-1);
}

void
nidh (dckey *priv, dckey *pub, char *priv_id, char *pub_id, char *label)
{
  rawpub rpub;
  rawpriv rpriv;

  int reserve;
  /* Let's name it that! */

  /* step 0: check that the private and public keys are compatible,
     i.e., they use the same group parameters */
  if ((-1 == get_rawpub (&rpub, pub)) 
      || (-1 == get_rawpriv (&rpriv, priv))) {
    printf ("%s: trouble importing GMP values from ElGamal-like keys\n",
	    getprogname ());

    printf ("priv:\n%s\n", dcexport_priv (priv));
    printf ("pub:\n%s\n", dcexport_pub (pub));

    exit (-1);    
  } else if (mpz_cmp (rpub.p, rpriv.p)
	     || mpz_cmp (rpub.q, rpriv.q)
	     || mpz_cmp (rpub.g, rpriv.g)) {
        printf ("%s:  the private and public keys are incompatible\n",
	    getprogname ());
        printf ("priv:\n%s\n", dcexport_priv (priv));
        printf ("pub:\n%s\n", dcexport_pub (pub));

        exit (-1);
  } else {
    
    /* step 1a: compute the Diffie-Hellman secret
                (use mpz_init, mpz_powm, mpz_clear; look at elgamal.c in 
                 the libdcrypt source directory for sample usage 
     */
    char *Diffie_Hellman_Secret_String = 0;
    {
      
      mpz_t dhSecretInt;
      mpz_init(dhSecretInt);
      mpz_powm(dhSecretInt, rpub.y, rpriv.x, rpub.p); 
      reserve = cat_mpz(&Diffie_Hellman_Secret_String, dhSecretInt); /* EC need 0; MALLOC */
      mpz_clear(dhSecretInt);
      if (reserve) {
          free(Diffie_Hellman_Secret_String);
          printf("error allocating memory\n");
          exit(1);
      }
      /* printf("Diffie_Hellman_Secret_String: %s\n",Diffie_Hellman_Secret_String); */
    }

    /* step 1b: order the IDs lexicographically */
    char *firstId = NULL, *secondId = NULL;
    
    if (strcmp (priv_id, pub_id) < 0) {
      firstId = priv_id;
      secondId = pub_id;
    } else {
      firstId = pub_id;
      secondId = priv_id;
    }    
    
    /* step 1c: hash DH secret and ordered id pair into a master key */
    char key_master[20];
    {
      sha1_ctx shaCipherText;
      sha1_init(&shaCipherText);
      sha1_update(&shaCipherText, Diffie_Hellman_Secret_String, strlen(Diffie_Hellman_Secret_String));

      char *id12;
      size_t len1, len2;
      len1 = strlen(firstId); len2 = strlen(secondId);
      id12 = (char*)malloc(len1+len2+1); /* +1 for \0 */
      strcpy(id12, firstId);
      strcat(id12, secondId);
      assert(strlen(id12) == len1+len2); 
      sha1_update(&shaCipherText, id12, len1+len2);
      free(id12);
      
      sha1_final(&shaCipherText, (void*)key_master);
      /*20 bytes*/
      
    }    
    
    /* step 2: derive the shared key from the label and the master key */
    /*I will work with minimum requirement satisfaction model. Thanks to the open source community for providing me with enough reasoning for that.*/
    char sizeofkey[32];
    {
      char sizeofkey_0[20];
      size_t len0 = strlen(label)+7;
      char *label0 = (char*)malloc(len0);
      strcpy(label0, label);
      strcat(label0, "AES-CTR");
      hmac_sha1(key_master, 20, sizeofkey_0, label0, len0);
      free(label0);

      char sizeofkey_1[20];
      size_t len1 = strlen(label)+9;
      char *label1 = (char*)malloc(len1);
      strcpy(label1, label);
      strcat(label1, "CBC-MAC");
      hmac_sha1(key_master, 20, sizeofkey_1, label1, len1);
      free(label1);

      strncpy(sizeofkey, sizeofkey_0, 16);
      strncpy(sizeofkey+16, sizeofkey_1, 16);
    
    }
    
    /*
	step 3: armor the shared key and write it to file.
    Filename should be of the form <label>-<priv_id>.b64
	 
	size_t fn_len = strlen(label)+1+strlen(priv_id)+1+strlen(pub_id)+4+1;
	*/

    char *fn = (char *) malloc(32);
	fn = armor64(sizeofkey, 32);
	*(fn + 32) = '\0';
	int fdsk;
	fdsk = open (label, O_WRONLY|O_TRUNC|O_CREAT, 0600);
	int status;
	status = write (fdsk, fn, strlen (fn));
	printf("value of status: %d\n", status);
	status = write (fdsk, "\n", 1);
	printf("value of status: %d\n", status);
    free (fn);
    close (fdsk);	
  }
}

int
main (int argc, char **argv)
{
  int arg_idx = 0;
  char *privcert_file = NULL;
  char *pubcert_file = NULL;
  char *priv_file = NULL;
  char *pub_file = NULL;
  char *priv_id = NULL;
  char *pub_id = NULL;
  char *label = DEFAULT_LABEL;
  dckey *priv = NULL;
  dckey *pub = NULL;
  cert *priv_cert = NULL;
  cert *pub_cert = NULL;
  
  printf("argc count is: %d\n", argc);
  if((argc < 7) || (argc > 8))
  {
   printf("Invalid number of arguments!!!\n");
   usage (argv[0], argc);
  }
  printf("argc value is: %d\n", argc);
  ri ();

  priv_file = argv[++arg_idx];
  privcert_file = argv[++arg_idx];
  priv_id = argv[++arg_idx];
  pub_file  = argv[++arg_idx];
  pubcert_file = argv[++arg_idx];
  pub_id = argv[++arg_idx];
  if (argc - 2 == arg_idx) {
    /* there was a label */
    label = argv[++arg_idx];
  }

  pub_cert = pki_check(pubcert_file, pub_file, pub_id);
  /* check above won't return if something was wrong */
  pub = pub_cert->public_key;

  if (!cert_verify (priv_cert = cert_read (privcert_file))) {
      printf ("%s: trouble reading certificate from %s, "
	      "or certificate expired\n", getprogname (), privcert_file);
      perror (getprogname ());

      exit (-1);
  } else if (!dcareequiv(pub_cert->issuer,priv_cert->issuer)) {
    printf ("%s: certificates issued by different CAs.\n",
	    getprogname ());
    printf ("\tOwn (%s's) certificate in %s\n", priv_id, privcert_file);
    printf ("\tOther (%s's) certificate in %s\n", pub_id, pubcert_file);
  } else {
    priv = priv_from_file (priv_file);
    
    nidh (priv, pub, priv_id, pub_id, label);
  }

  return 0;
}
