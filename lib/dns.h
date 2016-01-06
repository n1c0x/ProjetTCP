void dns(const u_char* packet);
void styled_print(char* style, char* text);

void dns(const u_char* packet){
	styled_print("bold","DNS");

	int identification;
	identification = *packet;
	printf("ID: %x\n", identification);
}