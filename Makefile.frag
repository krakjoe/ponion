onion: $(BUILD_BINARY_ONION)

$(BUILD_BINARY_ONION): $(PHP_GLOBAL_OBJS) $(PHP_BINARY_OBJS) $(PHP_ONION_OBJS)
	$(BUILD_ONION)

install-onion: $(BUILD_BINARY_ONION)
	@echo "Installing onion server:         $(INSTALL_ROOT)$(bindir)/"
	@$(mkinstalldirs) $(INSTALL_ROOT)$(bindir)
	@$(mkinstalldirs) $(INSTALL_ROOT)$(localstatedir)/log
	@$(mkinstalldirs) $(INSTALL_ROOT)$(localstatedir)/run
	@$(INSTALL) -m 0755 $(BUILD_BINARY_ONION) $(INSTALL_ROOT)$(bindir)/$(program_prefix)php-onion$(program_suffix)$(EXEEXT)

clean-onion:
	@echo "Cleaning onion object files ..."
	find sapi/onion/ -name *.lo -o -name *.o | xargs rm -f

.PHONY: clean-onion


