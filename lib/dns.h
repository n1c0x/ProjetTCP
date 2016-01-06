//void dns(const u_char* packet);
void styled_print(char* style, char* text);

int arg_v;

void dns(const u_char* packet){
	styled_print("bold","DNS");
	if (arg_v != 1){
		int identification;
		identification = *packet;
		printf("ID: %x\n", identification);
	}
	
}