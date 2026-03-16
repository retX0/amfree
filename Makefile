CC      = clang
CFLAGS  = -arch arm64 -Wall -Wextra -I include -I .
AS      = clang
ASFLAGS = -arch arm64
BUILD   = build
BIN     = bin

SRCS    = $(wildcard src/*.c)
OBJS    = $(patsubst src/%.c,$(BUILD)/%.o,$(SRCS))

.PHONY: all shellcode test clean

all: $(BIN)/amfree $(BIN)/test_ent

$(BUILD) $(BIN):
	@mkdir -p $@

# --- Build-time probes ---
$(BUILD)/probe_ivar: shellcode/probe_ivar.m | $(BUILD)
	@$(CC) -arch arm64 -lobjc -o $@ $<

$(BUILD)/ivar_offset.mk: $(BUILD)/probe_ivar
	@echo "IVAR_CODE_OFFSET=$$($(BUILD)/probe_ivar)" > $@

-include $(BUILD)/ivar_offset.mk

# --- Shellcode ---
$(BUILD)/hook.o: shellcode/hook.S shellcode/data_layout.h $(BUILD)/ivar_offset.mk | $(BUILD)
	$(AS) $(ASFLAGS) -I . -DIVAR_CODE_OFFSET=$(IVAR_CODE_OFFSET) -c $< -o $@

# --- All C sources get SLOT_DATA_PAGE_PTR + IVAR_CODE_OFFSET ---
$(BUILD)/%.o: src/%.c $(BUILD)/hook.o | $(BUILD)
	@DP_OFFSET=$$(nm $(BUILD)/hook.o | grep ' _dp_slot' | awk '{print "0x"$$1}'); \
	$(CC) $(CFLAGS) -DSLOT_DATA_PAGE_PTR=$$DP_OFFSET -DIVAR_CODE_OFFSET=$(IVAR_CODE_OFFSET) -c $< -o $@

# --- Link ---
$(BIN)/amfree: $(OBJS) $(BUILD)/hook.o | $(BIN)
	$(CC) $(CFLAGS) -lobjc -o $@ $^

$(BIN)/test_ent: tests/test_entitlements.c | $(BIN)
	$(CC) $(CFLAGS) -framework Security -framework CoreFoundation -o $@ $<
	codesign -s - --entitlements tests/test_entitlements.plist -f $@

shellcode: $(BUILD)/hook.o
	@size -m $< | grep inject

test: $(BIN)/amfree $(BIN)/test_ent
	@echo "=== Restarting amfid ==="
	@sudo killall -9 debugserver 2>/dev/null || true
	@sleep 1
	@sudo killall -9 amfid 2>/dev/null || true
	@sudo launchctl kickstart -k system/com.apple.MobileFileIntegrity
	@pgrep -x amfid > /dev/null 2>&1 || { echo "[FATAL] amfid did not restart"; exit 1; }
	@echo "=== Injecting ==="
	sudo $(BIN)/amfree
	@echo "=== Testing ==="
	@$(BIN)/test_ent && echo "[PASS]" || echo "[FAIL] $$?"
	@pgrep -x amfid > /dev/null && echo "[OK] amfid alive" || echo "[FAIL] amfid dead"

clean:
	rm -rf $(BUILD) $(BIN)
