#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>

#define DELTA 0x9e3779b9
#define _CRT_SECURE_NO_WARNINGS


typedef union {
	unsigned char strKey[17];	
	unsigned int intKey[4];
} Key; //key ����ü 

typedef union {
	unsigned char strContent[8];	 
	unsigned int intContent[2];	
} Content; //���� ����ü 

char pwd[17]; // ����� ��ȣ 
Key key; // ����� Ű 


void makePwd(){ // ����� ��ȣ �Է� 
	int i;
	int len;
	
	do {
		printf("����� ��ȣ �Է�(10~16�ڸ�) : ");
		scanf("%s", pwd);
		len = strlen(pwd);
	}while (len < 10);	//10�ڸ� ���� ��ȣ �Է� �ް� 
	
	for (i = len; i < 16; i++)	// ������ ��Ʈ 0���� �е� 
		pwd[i] = '0';
	pwd[16] = '\0';

	for (i = 0; i < 16; i++) // ��ȣ�� Ű�� ���� 
		key.strKey[i] = pwd[i];
	key.strKey[16] = '\0'; 
} 

void EncryptAlgorithm(unsigned int v[], unsigned int k[]) {	//	TEA encrypt algorithm
	int sum = 0;
	for (int i = 0; i < 32; i++) {
		sum += DELTA;
		v[0] += (v[1] + sum) ^ ((v[1] << 4) + k[0]) ^ ((v[1] >> 5) + k[1]);
		v[1] += (v[0] + sum) ^ ((v[0] << 4) + k[2]) ^ ((v[0] >> 5) + k[3]);
	}
}

void DecryptAlgorithm(unsigned int v[], unsigned int k[]) {	//	TEA decrypt algorithm
	int sum = 0;
	
	for(int i=0; i<32; i++)
		sum += DELTA;
		
	for (int i = 0; i < 32; i++) {
		v[1] -= (v[0] + sum) ^ ((v[0] << 4) + k[2]) ^ ((v[0] >> 5) + k[3]);
		v[0] -= (v[1] + sum) ^ ((v[1] << 4) + k[0]) ^ ((v[1] >> 5) + k[1]);
		sum -= DELTA;
	}
}

void Encrypt(char* mode, char* fname, unsigned int key[]){
	Content header; //��� 
	Content readContent; // ���� 
	Content IV; // ó�� ���� 
	Content first; // CBCó�� �� 
	
	IV.intContent[0] = rand(); // ó�� ���� �����ϰ� 
	IV.intContent[1] = rand();
	
	FILE *oldFile = fopen(fname, "rb"); //Ŀ�ǵ�� �Է� ���� ���� ���� 
	char newFname[100]; 
	strcpy(newFname, fname);
	strcat(newFname, ".tea"); // ���ο� tea ���� �̸�  
	FILE *newFile = fopen(newFname, "wb");// tea ���� ���� 
	
	header.strContent[0] = 'T';
    header.strContent[1] = 'E';
	header.strContent[2] = 'A';
    header.strContent[3] = '\0';
    header.strContent[4] = 'E';
    header.strContent[5] = 'C';
    header.strContent[6] = 'B';
    header.strContent[7] = '\0';
	
	if(!strcmp(mode, "ecb")){ // ecb��� 
		
		EncryptAlgorithm(header.intContent, key);// ��� ��ȣȭ 
		fwrite(&header, 1, 8, newFile); // tea���Ͽ� ��� ��ȣȭ ���� �Է� 
		
		while(1){ // ���� ���� ���ο� ���Ͽ� �Է� 		
			int block = fread(&readContent, 1, 8, oldFile); // ���� ���Ͽ��� ���� 8��Ʈ�� �ҷ����� 
			
			if(block==0){
				break; //���� �� ������ Ż�� 
			}
			EncryptAlgorithm(readContent.intContent, key); // ���� ��ȣȭ 
			fwrite(&readContent, 1, 8, newFile); // ���Ͽ� �Է� 
		}
		printf("��ȣȭ �Ϸ�");
		fclose(oldFile); // ���� �ݱ� 
 		fclose(newFile);
	}
	else if(!strcmp(mode, "cbc")){ //CBC �϶� 
		EncryptAlgorithm(header.intContent, key); // ��� ��ȣȭ 
		
		first = header; 
		fwrite(&IV, 1, 8, newFile); 
		fwrite(&header, 1, 8, newFile);
		
		while(1){
			int block = fread(&readContent, 1, 8, oldFile);
			int cnt =0;
			
			if(block == 0){
				break;
			}
			if(cnt ==0){ //�� ó������ �̴ϼ� ���ͷ� ��ȣȭ 
				readContent.intContent[0] ^= IV.intContent[0];
				readContent.intContent[1] ^= IV.intContent[1];
				cnt++;
			}
			else{ //���Ŀ��� ���� ������ ��ȣȭ 
				readContent.intContent[0] ^= first.intContent[0];
				readContent.intContent[1] ^= first.intContent[1];
			}
			first = readContent;
			EncryptAlgorithm(readContent.intContent, key); //���� ��ȣȭ 
			fwrite(&readContent, 1, 8, newFile);
		}
		printf("��ȣȭ ����");
		fclose(oldFile);
		fclose(newFile); 
	}
	
}

void Decrypt(char* mode, char* fname, unsigned int key[]){
	Content header;
	Content readContent;
	Content IV;
	Content first;
	
	FILE *oldFile = fopen(fname, "rb");
	char newFname[100];
	for (int i = 0; i < strlen(fname) - 4; i++)	// .tea ����
		newFname[i] = fname[i];
	newFname[strlen(fname) - 4] = '\0';
	FILE *newFile = fopen(newFname, "wb");

	if(!strcmp(mode, "ecb")){
		int block = fread(&header, 1, 8, oldFile);
		
		DecryptAlgorithm(header.intContent, key); // ��ȣȭ  
		
		if(header.strContent[0] == 'T'&&
		   header.strContent[1] == 'E'&&
		   header.strContent[2] == 'A'&&
		   header.strContent[3] == '\0'&&
		   header.strContent[4] == 'E'&&
		   header.strContent[5] == 'C'&&
		   header.strContent[6] == 'B'&&
		   header.strContent[7] == '\0'
		   ){
		   	printf("��ȣ ��ġ\n");
		}
		else{
			printf("��ȣ ����ġ");
			exit(1); 
		}

		while(1){
			block = fread(&readContent, 1, 8, oldFile); //�о�� 
			
			if(block == 0){
				break;
			}
			DecryptAlgorithm(readContent.intContent, key); // ���� ��ȣȭ 
			fwrite(&readContent, 1, 8, newFile); //�� ���Ͽ� ���� �Է� 
		}
		printf("��ȣȭ �Ϸ�");
		fclose(oldFile); //���� �ݱ� 
		fclose(newFile);
	}
	else if(!strcmp(mode, "cbc")){
		fread(&IV, 1, 8, oldFile);
		fread(&header, 1, 8, oldFile);
		
		DecryptAlgorithm(header.intContent, key);
		
		if(header.strContent[0] == 'T'&&
		   header.strContent[1] == 'E'&&
		   header.strContent[2] == 'A'&&
		   header.strContent[3] == '\0'&&
		   header.strContent[4] == 'E'&&
		   header.strContent[5] == 'C'&&
		   header.strContent[6] == 'B'&&
		   header.strContent[7] == '\0'){
			printf("��ȣ ��ġ");
		}
		else{
			printf("��ȣ ����ġ");
			exit(1); 
		}
		
		while(1){ //��ȣȭ�� ���� 
			int block = fread(&readContent, 1, 8, oldFile);
			int cnt = 0;
			
			if(block == 0){
				break;
			}
			
			DecryptAlgorithm(readContent.intContent, key);
			if(cnt==0){
				readContent.intContent[0] ^= IV.intContent[0];
				readContent.intContent[1] ^= IV.intContent[1];
				cnt++;
			}
			else{
				readContent.intContent[0] ^= first.intContent[0];
				readContent.intContent[1] ^= first.intContent[1];
			}	
			first = readContent;
			fwrite(&readContent, 1, 8, newFile);
		}
		fclose(oldFile); // ���� �ݱ� 
		fclose(newFile);
	}
}

int main(int argc, char *argv[]) {
	if(!strcmp(argv[1],"-e")){
		makePwd();	
        Encrypt(argv[2],argv[3], key.intKey);
	}	
    else if(!strcmp(argv[1],"-d")){
    	makePwd();
        Decrypt(argv[2],argv[3], key.intKey);
	}
    else
        printf("��ɾ� ����");
}
