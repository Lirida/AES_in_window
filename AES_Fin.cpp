// AES_Fin.cpp: ������� ���� �������.
#include "stdafx.h"
#include "Form1.h"

using namespace AES_Fin;

[STAThreadAttribute]
int main(array<System::String ^> ^args)
{
	// ��������� ���������� �������� Windows XP �� �������� �����-���� ��������� ����������
	Application::EnableVisualStyles();
	Application::SetCompatibleTextRenderingDefault(false); 

	// �������� �������� ���� � ��� ������
	Application::Run(gcnew Form1());
	
	return 0;
}
