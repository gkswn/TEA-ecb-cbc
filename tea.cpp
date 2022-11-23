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
} Key; //key 공용체 

typedef union {
	unsigned char strContent[8];	 
	unsigned int intContent[2];	
} Content; //내용 공용체 

char pwd[17]; // 사용자 암호 
Key key; // 사용자 키 


void makePwd(){ // 사용자 암호 입력 
	int i;
	int len;
	
	do {
		printf("사용자 암호 입력(10~16자리) : ");
		scanf("%s", pwd);
		len = strlen(pwd);
	}while (len < 10);	//10자리 까지 암호 입력 받게 
	
	for (i = len; i < 16; i++)	// 나머지 비트 0으로 패딩 
		pwd[i] = '0';
	pwd[16] = '\0';

	for (i = 0; i < 16; i++) // 암호를 키로 받음 
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
	Content header; //헤더 
	Content readContent; // 내용 
	Content IV; // 처음 벡터 
	Content first; // CBC처음 블럭 
	
	IV.intContent[0] = rand(); // 처음 벡터 랜덤하게 
	IV.intContent[1] = rand();
	
	FILE *oldFile = fopen(fname, "rb"); //커맨드로 입력 받은 파일 오픈 
	char newFname[100]; 
	strcpy(newFname, fname);
	strcat(newFname, ".tea"); // 새로운 tea 파일 이름  
	FILE *newFile = fopen(newFname, "wb");// tea 파일 오픈 
	
	header.strContent[0] = 'T';
    header.strContent[1] = 'E';
	header.strContent[2] = 'A';
    header.strContent[3] = '\0';
    header.strContent[4] = 'E';
    header.strContent[5] = 'C';
    header.strContent[6] = 'B';
    header.strContent[7] = '\0';
	
	if(!strcmp(mode, "ecb")){ // ecb모드 
		
		EncryptAlgorithm(header.intContent, key);// 헤더 암호화 
		fwrite(&header, 1, 8, newFile); // tea파일에 헤더 암호화 내용 입력 
		
		while(1){ // 파일 내용 새로운 파일에 입력 		
			int block = fread(&readContent, 1, 8, oldFile); // 원래 파일에서 내용 8비트씩 불러오기 
			
			if(block==0){
				break; //파일 다 읽으면 탈출 
			}
			EncryptAlgorithm(readContent.intContent, key); // 내용 암호화 
			fwrite(&readContent, 1, 8, newFile); // 파일에 입력 
		}
		printf("암호화 완료");
		fclose(oldFile); // 파일 닫기 
 		fclose(newFile);
	}
	else if(!strcmp(mode, "cbc")){ //CBC 일때 
		EncryptAlgorithm(header.intContent, key); // 헤더 암호화 
		
		first = header; 
		fwrite(&IV, 1, 8, newFile); 
		fwrite(&header, 1, 8, newFile);
		
		while(1){
			int block = fread(&readContent, 1, 8, oldFile);
			int cnt =0;
			
			if(block == 0){
				break;
			}
			if(cnt ==0){ //맨 처음에는 이니셜 벡터로 암호화 
				readContent.intContent[0] ^= IV.intContent[0];
				readContent.intContent[1] ^= IV.intContent[1];
				cnt++;
			}
			else{ //이후에는 앞의 블럭으로 암호화 
				readContent.intContent[0] ^= first.intContent[0];
				readContent.intContent[1] ^= first.intContent[1];
			}
			first = readContent;
			EncryptAlgorithm(readContent.intContent, key); //내용 암호화 
			fwrite(&readContent, 1, 8, newFile);
		}
		printf("암호화 종료");
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
	for (int i = 0; i < strlen(fname) - 4; i++)	// .tea 제거
		newFname[i] = fname[i];
	newFname[strlen(fname) - 4] = '\0';
	FILE *newFile = fopen(newFname, "wb");

	if(!strcmp(mode, "ecb")){
		int block = fread(&header, 1, 8, oldFile);
		
		DecryptAlgorithm(header.intContent, key); // 복호화  
		
		if(header.strContent[0] == 'T'&&
		   header.strContent[1] == 'E'&&
		   header.strContent[2] == 'A'&&
		   header.strContent[3] == '\0'&&
		   header.strContent[4] == 'E'&&
		   header.strContent[5] == 'C'&&
		   header.strContent[6] == 'B'&&
		   header.strContent[7] == '\0'
		   ){
		   	printf("암호 일치\n");
		}
		else{
			printf("암호 불일치");
			exit(1); 
		}

		while(1){
			block = fread(&readContent, 1, 8, oldFile); //읽어옴 
			
			if(block == 0){
				break;
			}
			DecryptAlgorithm(readContent.intContent, key); // 내용 복호화 
			fwrite(&readContent, 1, 8, newFile); //새 파일에 내용 입력 
		}
		printf("복호화 완료");
		fclose(oldFile); //파일 닫기 
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
			printf("암호 일치");
		}
		else{
			printf("암호 불일치");
			exit(1); 
		}
		
		while(1){ //암호화의 역순 
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
		fclose(oldFile); // 파일 닫기 
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
        printf("명령어 오류");
}
