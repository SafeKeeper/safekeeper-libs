all: all_b64

php: all_php_cpp

all_b64:
	$(MAKE) -C libb64

all_php_cpp:
	$(MAKE) -C php_cpp

clean: clean_b64 clean_php_cpp
	
clean_b64:
	$(MAKE) -C lib_uke clean;

clean_php_cpp:
	$(MAKE) -C lib_uke clean;
