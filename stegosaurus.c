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
    FREE_IMAGE_FORMAT format;
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

void encryption_error_handler(void) {
    fprintf(stderr, "Failed to encrypt text\n");
    exit(EXIT_FAILURE);
}

void data_too_large_error_handler(int maxCapacity) {
    fprintf(stderr, "Data too large to embed in the image. Maximum capacity is %zu bytes\n", maxCapacity);
    exit(EXIT_FAILURE);
}

void unsupported_image_error_handler(void) {
    fprintf(stderr, "Unsupported image format. Only 24-bit and 32-bit images are supported\n");
    exit(EXIT_FAILURE);
}

void convert_to_bmp(char* input_filename, EncryptionInfo* encInfo) {
    FREE_IMAGE_FORMAT format = FreeImage_GetFileType(input_filename, 0);
    if (format == FIF_UNKNOWN) {
        format = FreeImage_GetFIFFromFilename(input_filename);
    }
    if (format == FIF_UNKNOWN) {
        unsupported_image_error_handler(input_filename);
    }
    encInfo->format = format;
    encInfo->bitmap = FreeImage_Load(format, input_filename, 0);
    if (!encInfo->bitmap) {
        image_load_error_handler(input_filename);
       }
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
            convert_to_bmp(argv[1], &encInfo);
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

void embedData(EncryptionInfo* encInfo, CipherInfo cipherInfo) {
    BYTE* bits = FreeImage_GetBits(encInfo->bitmap);
    unsigned width = FreeImage_GetWidth(encInfo->bitmap);
    unsigned height = FreeImage_GetHeight(encInfo->bitmap);
    unsigned pitch = FreeImage_GetPitch(encInfo->bitmap);
    unsigned bitsPerPixel = FreeImage_GetBPP(encInfo->bitmap);

    if (bitsPerPixel != 24 && bitsPerPixel != 32) {
        unsupported_image_error_handler();
    }

    size_t maxCapacity = (width * height * (bitsPerPixel / 8)) / 8;
    if (cipherInfo.cipherLength > maxCapacity) {
        data_too_large_error_handler(maxCapacity);
    }

    size_t data_idx = 0;

    for (unsigned y = 0; y < height; ++y) {
        BYTE* pixel = bits + y * pitch;
        for (unsigned x = 0; x < width; ++x) {
            for (unsigned channel = 0; channel < (bitsPerPixel / 8); ++channel) {
                if (data_idx < cipherInfo.cipherLength * 8) {
                    // Embed one bit of data into the LSB of the current channel
                    pixel[channel] = (pixel[channel] & 0xFE) | ((cipherInfo.cipherText[data_idx / 8] >> (7 - (data_idx % 8))) & 1);
                    data_idx++;
                }
            }
            pixel += (bitsPerPixel / 8); // Move to the next pixel
        }
    }

    if (data_idx < cipherInfo.cipherLength * 8) {
        fprintf(stderr, "Warning: Not all data was embedded into the image. Image may be too small\n");
    }
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
    printf("%s\n", encInfo.text);
    printf("%d\n", encInfo.textLength);
    printf("%s\n", encInfo.text);
    CipherInfo cipherInfo = encrypt_text(encInfo);
    printf("Cipher text: %s\n", cipherInfo.cipherText);
    printf("Cipher length: %d\n", cipherInfo.cipherLength);
    // free_encryption_info(&encInfo);
    return 0;
}
