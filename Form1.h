#pragma once
#include "stdafx.h"
#include "Form1.h"
#define Nb 4

namespace AES_Fin {
	
	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;

	int Nr=128;
	int Nk=0;
	unsigned char in[16], out[16], state[4][4];
	unsigned char RoundKey[240];
	unsigned char Key[32];
	unsigned char temp[16] = {0x00  ,0x01  ,0x02  ,0x03  ,0x04  ,0x05  ,0x06  ,0x07  ,0x08  ,0x09  ,0x0a  ,0x0b  ,0x0c  ,0x0d  ,0x0e  ,0x0f};
	unsigned char temp2[16]= {0x00  ,0x11  ,0x22  ,0x33  ,0x44  ,0x55  ,0x66  ,0x77  ,0x88  ,0x99  ,0xaa  ,0xbb  ,0xcc  ,0xdd  ,0xee  ,0xff};
	int flag = 0;

	int getSBoxValue(int num)
{
	int sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
	};
	return sbox[num];
}

int getInvSBoxValue(int num)
{
	int invsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };
	return invsbox[num];
}

int Rcon[255] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
	0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
	0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
	0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
	0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
	0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
	0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
	0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
	0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
	0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
	0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
	0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
	0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
	0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
	0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
	0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb  };

void KeyExpansion()
{
	int i,j,Nr = 10;
	unsigned char temp[4],k;
	
	for(i=0; i<Nk; i++)
	{
		RoundKey[i*4]=Key[i*4];
		RoundKey[i*4+1]=Key[i*4+1];
		RoundKey[i*4+2]=Key[i*4+2];
		RoundKey[i*4+3]=Key[i*4+3];
	}

	while (i < (Nb * (Nr+1)))
	{
		for(j=0; j<4; j++)
		{
			temp[j]=RoundKey[(i-1) * 4 + j];
		}
		if (i % Nk == 0)
		{
			k = temp[0];
			temp[0] = temp[1];
			temp[1] = temp[2];
			temp[2] = temp[3];
			temp[3] = k;

			temp[0]=getSBoxValue(temp[0]);
			temp[1]=getSBoxValue(temp[1]);
			temp[2]=getSBoxValue(temp[2]);
			temp[3]=getSBoxValue(temp[3]);

			temp[0] =  temp[0] ^ Rcon[i/Nk];
		}
		else if (Nk > 6 && i % Nk == 4)
		{
			temp[0]=getSBoxValue(temp[0]);
			temp[1]=getSBoxValue(temp[1]);
			temp[2]=getSBoxValue(temp[2]);
			temp[3]=getSBoxValue(temp[3]);
		}

		RoundKey[i*4+0] = RoundKey[(i-Nk)*4+0] ^ temp[0];
		RoundKey[i*4+1] = RoundKey[(i-Nk)*4+1] ^ temp[1];
		RoundKey[i*4+2] = RoundKey[(i-Nk)*4+2] ^ temp[2];
		RoundKey[i*4+3] = RoundKey[(i-Nk)*4+3] ^ temp[3];
		i++;
	}
}

void AddRoundKey(int round) 
{
	int i,j;
	for(i=0; i<4; i++)
	{
		for(j=0; j<4; j++)
		{
			state[j][i] ^= RoundKey[round * Nb * 4 + i * Nb + j];
		}
	}
}

void SubBytes()
{
	int i,j;
	for(i=0; i<4; i++)
	{
		for(j=0; j<4; j++)
		{
			state[i][j] = getSBoxValue(state[i][j]);

		}
	}
}

void InvSubBytes()
{
	int i,j;
	for(i=0; i<4; i++)
	{
		for(j=0; j<4; j++)
		{
			state[i][j] = getInvSBoxValue(state[i][j]);

		}
	}
}

void ShiftRows()
{
	unsigned char temp;

	temp=state[1][0];
	state[1][0]=state[1][1];
	state[1][1]=state[1][2];
	state[1][2]=state[1][3];
	state[1][3]=temp;

	temp=state[2][0];
	state[2][0]=state[2][2];
	state[2][2]=temp;

	temp=state[2][1];
	state[2][1]=state[2][3];
	state[2][3]=temp;

	temp=state[3][0];
	state[3][0]=state[3][3];
	state[3][3]=state[3][2];
	state[3][2]=state[3][1];
	state[3][1]=temp;
}

void InvShiftRows()
{
	unsigned char temp;

	temp=state[1][3];
	state[1][3]=state[1][2];
	state[1][2]=state[1][1];
	state[1][1]=state[1][0];
	state[1][0]=temp;

	temp=state[2][0];
	state[2][0]=state[2][2];
	state[2][2]=temp;
	temp=state[2][1];
	state[2][1]=state[2][3];
	state[2][3]=temp;

	temp=state[3][3];
	state[3][3]=state[3][2];
	state[3][2]=state[3][1];
	state[3][1]=state[3][0];
	state[3][0]=temp;
}

// xtime is a macro that finds the product of {02} and the argument to xtime modulo {1b}  
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))

void MixColumns()
{
	int i;
	unsigned char Tmp, Tm, t;
	for(i=0; i<4; i++)
	{	
		t=state[0][i];
		Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];

		Tm = state[0][i] ^ state[1][i]; 
		Tm = xtime(Tm); 
		state[0][i] ^= Tm ^ Tmp;

		Tm = state[1][i] ^ state[2][i]; 
		Tm = xtime(Tm); 
		state[1][i] ^= Tm ^ Tmp;

		Tm = state[2][i] ^ state[3][i];
		Tm = xtime(Tm); 
		state[2][i] ^= Tm ^ Tmp;

		Tm = state[3][i] ^ t; 
		Tm = xtime(Tm); 
		state[3][i] ^= Tm ^ Tmp;
	}
}

void InvMixColumns()
{
	int i;
	unsigned char Tmp, Tm, t;
	for(i=4; i>0; i--)
	{	
		t=state[3][i];
		Tmp = state[3][i] ^ state[2][i] ^ state[1][i] ^ state[0][i];

		Tm = state[3][i] ^ state[1][i]; 
		Tm = xtime(Tm); 
		state[3][i] ^= Tm ^ Tmp;

		Tm = state[2][i] ^ state[2][i]; 
		Tm = xtime(Tm); 
		state[2][i] ^= Tm ^ Tmp;

		Tm = state[1][i] ^ state[3][i];
		Tm = xtime(Tm); 
		state[1][i] ^= Tm ^ Tmp;

		Tm = state[0][i] ^ t; 
		Tm = xtime(Tm); 
		state[0][i] ^= Tm ^ Tmp;
	}
}

void Cipher()
{
	int i, j, round=0;

	for(i=0; i<4; i++)
	{
		for(j=0; j<4; j++)
		{
			state[j][i] = in[i*4 + j];
		}
	}

	AddRoundKey(0); 

	for(round=1; round<Nr; round++)
	{
		SubBytes();
		ShiftRows();
		MixColumns();
		AddRoundKey(round);
	}
	
	SubBytes();
	ShiftRows();
	AddRoundKey(Nr);

	for(i=0; i<4; i++)
	{
		for(j=0; j<4; j++)
		{
			out[i*4+j]=state[j][i];
		}
	}
}

void InvCipher()
{
int i, j, round=0;

	for(i=0; i<4; i++)
	{
		for(j=0; j<4; j++)
		{
			state[j][i] = in[i*4 + j];
		}
	}

	AddRoundKey(Nr); 

	for(round=Nr-1; round>0; round--)
	{
		InvShiftRows();
		InvSubBytes();
		AddRoundKey(round);
		InvMixColumns();
	}
	InvShiftRows();
	InvSubBytes();
	AddRoundKey(0);
	
	for(i=0; i<4; i++)
	{
		for(j=0; j<4; j++)
		{
			out[i*4+j]=state[j][i];
		}
	}
}

	
	
	public ref class Form1 : public System::Windows::Forms::Form
	{
	public:
		Form1(void)
		{
			InitializeComponent();
		}

	protected:
		~Form1()
		{
			if (components)
			{
				delete components;
			}
		}
	private: System::Windows::Forms::Label^  label1;
	private: System::Windows::Forms::Label^  label2;
	private: System::Windows::Forms::Label^  label3;
	private: System::Windows::Forms::Label^  label4;
	private: System::Windows::Forms::Button^  button1;
	private: System::Windows::Forms::Label^  label5;
	private: System::Windows::Forms::Button^  button2;
	private: System::Windows::Forms::Label^  label6;
	private: System::Windows::Forms::Label^  label7;
	protected: 

	private:
		System::ComponentModel::Container ^components;

#pragma region Windows Form Designer generated code

		void InitializeComponent(void)
		{
			this->label1 = (gcnew System::Windows::Forms::Label());
			this->label2 = (gcnew System::Windows::Forms::Label());
			this->label3 = (gcnew System::Windows::Forms::Label());
			this->label4 = (gcnew System::Windows::Forms::Label());
			this->button1 = (gcnew System::Windows::Forms::Button());
			this->label5 = (gcnew System::Windows::Forms::Label());
			this->button2 = (gcnew System::Windows::Forms::Button());
			this->label6 = (gcnew System::Windows::Forms::Label());
			this->label7 = (gcnew System::Windows::Forms::Label());
			this->SuspendLayout();
			// 
			// label1
			// 
			this->label1->AutoSize = true;
			this->label1->Font = (gcnew System::Drawing::Font(L"Times New Roman", 15.75F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point, 
				static_cast<System::Byte>(204)));
			this->label1->Location = System::Drawing::Point(55, 15);
			this->label1->Name = L"label1";
			this->label1->Size = System::Drawing::Size(344, 24);
			this->label1->TabIndex = 0;
			this->label1->Text = L"Advansed Encryption Standart (AES)";
			// 
			// label2
			// 
			this->label2->AutoSize = true;
			this->label2->Font = (gcnew System::Drawing::Font(L"Times New Roman", 12, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point, 
				static_cast<System::Byte>(204)));
			this->label2->Location = System::Drawing::Point(12, 80);
			this->label2->Name = L"label2";
			this->label2->Size = System::Drawing::Size(432, 19);
			this->label2->TabIndex = 1;
			this->label2->Text = L"Plaintext:                 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff";
			// 
			// label3
			// 
			this->label3->AutoSize = true;
			this->label3->Font = (gcnew System::Drawing::Font(L"Times New Roman", 12, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point, 
				static_cast<System::Byte>(204)));
			this->label3->Location = System::Drawing::Point(12, 125);
			this->label3->Name = L"label3";
			this->label3->Size = System::Drawing::Size(108, 19);
			this->label3->TabIndex = 2;
			this->label3->Text = L"Encrypted data: ";
			// 
			// label4
			// 
			this->label4->AutoSize = true;
			this->label4->Font = (gcnew System::Drawing::Font(L"Times New Roman", 12, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point, 
				static_cast<System::Byte>(204)));
			this->label4->Location = System::Drawing::Point(12, 171);
			this->label4->Name = L"label4";
			this->label4->Size = System::Drawing::Size(110, 19);
			this->label4->TabIndex = 3;
			this->label4->Text = L"Decrypted data: ";
			// 
			// button1
			// 
			this->button1->Location = System::Drawing::Point(228, 260);
			this->button1->Name = L"button1";
			this->button1->Size = System::Drawing::Size(99, 26);
			this->button1->TabIndex = 4;
			this->button1->Text = L"Encryption";
			this->button1->UseVisualStyleBackColor = true;
			this->button1->Click += gcnew System::EventHandler(this, &Form1::button1_Click);
			// 
			// label5
			// 
			this->label5->AutoSize = true;
			this->label5->Location = System::Drawing::Point(13, 281);
			this->label5->Name = L"label5";
			this->label5->Size = System::Drawing::Size(133, 13);
			this->label5->TabIndex = 5;
			this->label5->Text = L"Lidia Andrukhina, KI 10-01";
			// 
			// button2
			// 
			this->button2->Location = System::Drawing::Point(339, 260);
			this->button2->Name = L"button2";
			this->button2->Size = System::Drawing::Size(99, 26);
			this->button2->TabIndex = 6;
			this->button2->Text = L"Decryption";
			this->button2->UseVisualStyleBackColor = true;
			this->button2->Click += gcnew System::EventHandler(this, &Form1::button2_Click);
			// 
			// label6
			// 
			this->label6->AutoSize = true;
			this->label6->Font = (gcnew System::Drawing::Font(L"Times New Roman", 12, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point, 
				static_cast<System::Byte>(204)));
			this->label6->Location = System::Drawing::Point(135, 125);
			this->label6->Name = L"label6";
			this->label6->Size = System::Drawing::Size(0, 19);
			this->label6->TabIndex = 7;
			// 
			// label7
			// 
			this->label7->AutoSize = true;
			this->label7->Font = (gcnew System::Drawing::Font(L"Times New Roman", 12, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point, 
				static_cast<System::Byte>(204)));
			this->label7->Location = System::Drawing::Point(135, 171);
			this->label7->Name = L"label7";
			this->label7->Size = System::Drawing::Size(0, 19);
			this->label7->TabIndex = 8;
			// 
			// Form1
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(457, 306);
			this->Controls->Add(this->label7);
			this->Controls->Add(this->label6);
			this->Controls->Add(this->button2);
			this->Controls->Add(this->label5);
			this->Controls->Add(this->button1);
			this->Controls->Add(this->label4);
			this->Controls->Add(this->label3);
			this->Controls->Add(this->label2);
			this->Controls->Add(this->label1);
			this->Name = L"Form1";
			this->Text = L"Advansed Encryption Standart (AES)";
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion
	private: System::Void button1_Click(System::Object^  sender, System::EventArgs^  e) 
	{
		flag = 1;
		Nk = Nr / 32;
		Nr = Nk + 6;
		int i;
		long int str;
		for(i=0; i<Nk*4; i++)
		{
			Key[i]=temp[i];
			in[i]=temp2[i];
		}

		KeyExpansion();
		Cipher();

		char buf[2], finbuf [32];
		// for(i=0; i<Nk*4; i++)
		{
			int im = out[i];
			itoa (im, buf, 16);
			strcpy (finbuf, buf);
			for (int j=0; j<48; j++)
				label6->Text += finbuf[j];
		}
	}
	private: System::Void button2_Click(System::Object^  sender, System::EventArgs^  e) 
	{

	}
};
}

