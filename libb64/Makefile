all: all_src

all_src: all_build all_copy

all_build:
	$(MAKE) -C src

all_copy:
	$(shell cp src/libb64.a ./libb64.a)
	$(shell cp src/libb64.so ./libb64.so)
	
clean: clean_src clean_include
	rm -f *~ *.bak
	rm libb64.a
	rm libb64.so

clean_include:
	rm -f include/b64/*~

clean_src:
	$(MAKE) -C src clean;
		
distclean: clean distclean_src

distclean_src:
	$(MAKE) -C src distclean;

