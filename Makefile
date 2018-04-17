TOP_DIR = ~/git/sgx/linux-sgx
export TOP_DIR

all: all_tke all_uke all_b64

php: all_php_cpp

all_tke:
	$(MAKE) -C lib_tke

all_uke:
	$(MAKE) -C lib_uke

all_b64:
	$(MAKE) -C libb64

all_php_cpp:
	$(MAKE) -C php_cpp

clean: clean_tke clean_uke clean_b64 clean_php_cpp
	
clean_tke:
	$(MAKE) -C lib_tke clean;

clean_uke:
	$(MAKE) -C lib_uke clean;

clean_b64:
	$(MAKE) -C lib_uke clean;

clean_php_cpp:
	$(MAKE) -C lib_uke clean;
