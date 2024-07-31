#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <FreeImage.h>

typedef struct {
    char* key;
    char* iv;
    FIBITMAP* bitmap;
    char* text;
    int textLength;
} EncryptionInfo;

typedef struct {
    char* cipherText;
    int cipherLength;
} CipherInfo;

void usage_error_handler(void) {
    fprintf(stderr, "Usage: stegosaurus [--key key] [--iv iv] [--img imgname] [--text plaintext]\n");
    exit(EXIT_FAILURE);
}

void unsupported_image_error_handler(char* input_filename) {
    fprintf(stderr, "Unsupported image format: %s\n", input_filename);
    exit(EXIT_FAILURE);
}

void image_load_error_handler(char* input_filename) {
    fprintf(stderr, "Failed to load image: %s\n", input_filename);
    exit(EXIT_FAILURE);
}

void encryption_error(void) {
    fprintf(stderr, "Failed to encrypt text\n");
    exit(EXIT_FAILURE);
}

FIBITMAP* convert_to_bmp(char* input_filename) {
    FREE_IMAGE_FORMAT format = FreeImage_GetFileType(input_filename, 0);
    if (format == FIF_UNKNOWN) {
        format = FreeImage_GetFIFFromFilename(input_filename);
    }
    if (format == FIF_UNKNOWN) {
        unsupported_image_error_handler(input_filename);
    }

    FIBITMAP* bitmap = FreeImage_Load(format, input_filename, 0);
    if (!bitmap) {
        image_load_error_handler(input_filename);
    }

    return bitmap;
}

EncryptionInfo process_command_line(int argc, char* argv[]) {
    argv++;
    argc--;

    EncryptionInfo encInfo = {NULL, NULL, NULL, NULL};

    while (argc >= 2 && strncmp(argv[0], "--", 2) == 0 && strlen(argv[1]) > 0) {
        if (!strcmp(argv[0], "--key") && !encInfo.key) {
            encInfo.key = (char*)malloc(257);
            if (strlen(argv[1]) > 256) usage_error_handler();
            snprintf(encInfo.key, 257, "%s", argv[1]);
            argc -= 2;
            argv += 2;
        }
        else if (!strcmp(argv[0], "--iv") && !encInfo.iv) {
            encInfo.iv = (char*)malloc(129);
            if (strlen(argv[1]) > 128) usage_error_handler();
            snprintf(encInfo.iv, 129, "%s", argv[1]);
            argc -= 2;
            argv += 2;
        }
        else if (!strcmp(argv[0], "--img") && !encInfo.bitmap) {
            encInfo.bitmap = convert_to_bmp(argv[1]);
            argc -= 2;
            argv += 2;
        }
        else if (!strcmp(argv[0], "--text") && !encInfo.text) {
            encInfo.text = argv[1];
            encInfo.textLength = strlen(encInfo.text);
            argc -= 2;
            argv += 2;
        }
        else {
            usage_error_handler();
        }
    }
    if (!encInfo.key || !encInfo.iv || !encInfo.bitmap || !encInfo.text) {
        usage_error_handler();
    }
    if (argc) {
        // We have left over arguments - this is a problem
        usage_error_handler();
    }
    return encInfo;
}

CipherInfo encrypt_text(EncryptionInfo encInfo) {
    EVP_CIPHER_CTX* ctx;
    CipherInfo cipherInfo = { NULL, 0 };
    int len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        encryption_error();
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, encInfo.key, encInfo.iv)) {
        encryption_error();
    }

    // Give it another block
    cipherInfo.cipherText = (unsigned char*)malloc(encInfo.textLength + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    if (1 != EVP_EncryptUpdate(ctx, cipherInfo.cipherText, &len, encInfo.text, encInfo.textLength)) {
        encryption_error();
    }
    cipherInfo.cipherLength = len;

    if (1 != EVP_EncryptFinal_ex(ctx, cipherInfo.cipherText + len, &len)) {
        encryption_error();
    }
    cipherInfo.cipherLength += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    return cipherInfo;
}

void free_encryption_info(EncryptionInfo* encInfo) {
    if (encInfo->bitmap) {
        FreeImage_Unload(encInfo->bitmap);
    }
    if (encInfo->key) {
        free(encInfo->key);
    }
    if (encInfo->iv) {
        free(encInfo->iv);
    }
}

void free_cipher_info(CipherInfo* cipherInfo) {
    if (cipherInfo->cipherText) {
        free(cipherInfo->cipherText);
    }
}

int main(int argc, char* argv[]) {
    EncryptionInfo encInfo = process_command_line(argc, argv);
    CipherInfo cipherInfo = encrypt_text(encInfo);
    // free_encryption_info(&encInfo);
    return 0;
}
