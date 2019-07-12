######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_FLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_FLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_FLAGS += -O0 -g
else
	SGX_COMMON_FLAGS += -O2
endif

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

######## Library Settings ########


######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Cpp_Files := $(wildcard App/*.cpp)
App_Include_Paths := -I$(SGX_SDK)/include -I./Include

App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths)
# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
	App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
	App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cxx_Flags := $(App_C_Flags) $(SGX_COMMON_CXXFLAGS)
App_C_Flags += $(SGX_COMMON_CFLAGS)

App_Link_Flags := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -L. -lpthread 

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)
App_Name := app

######## Enclave Settings ########

Enclave_Version_Script := Enclave/Enclave.lds

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := $(wildcard Enclave/*.cpp)
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx -I./Include

CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	Enclave_C_Flags := -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector
else
	Enclave_C_Flags := -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector-strong
endif

Enclave_C_Flags += $(Enclave_Include_Paths)
Enclave_Cxx_Flags := $(Enclave_C_Flags) $(SGX_COMMON_CXXFLAGS) -nostdinc++
Enclave_C_Flasg += $(SGX_COMMON_CFLAGS)

# Enable the security flags
Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Common_Enclave_Link_Flags := $(Enclave_Security_Link_Flags) \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -L. -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections
Enclave_Link_Flags := $(Common_Enclave_Link_Flags) -Wl,--version-script=$(Enclave_Version_Script)

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := libenclave.so

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif

v2 = LAv2
ifdef $(v2)
	LAv2_MACRO = 1
else
	LAv2_MACRO = 0
endif	

.PHONY: all target
all: .config_$(Build_Mode)_$(SGX_ARCH)_$(LAv2_MACRO)
	@$(MAKE) target

ifeq ($(Build_Mode), HW_RELEASE)
target: $(Trust_Lib_Name) $(UnTrustLib_Name) Enclave.so $(App_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the enclaves (Enclave.so) first with your signing keys before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclaves use the following commands:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <key1> -enclave Enclave.so -out <$(Enclave_Name)> -config Enclave/Enclave.config.xml"
	@echo "You can also sign the enclaves using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
target: $(Trust_Lib_Name) $(UnTrustLib_Name) $(Enclave_Name) $(App_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

.config_$(Build_Mode)_$(SGX_ARCH)_$(LAv2_MACRO):
	@rm -rf .config_* $(App_Name) *.so *.a App/*.o Enclave/*.o Enclave/*_t.* Enclave/*_u.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)_$(LAv2_MACRO)

######## Library Objects ########

######## App Objects ########
Enclave/client_enclave_u.h: $(SGX_EDGER8R) Enclave/client_enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --use-prefix --untrusted ../Enclave/client_enclave.edl --search-path $(SGX_SDK)/include 
	@echo "GEN  =>  $@"

Enclave/client_enclave_u.c: Enclave/client_enclave_u.h

App/client_enclave_u.o: Enclave/client_enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp Enclave/client_enclave_u.h
	@$(CXX) $(App_Cxx_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): App/client_enclave_u.o $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


######## Enclave Objects ########

Enclave/client_enclave_t.h: $(SGX_EDGER8R) Enclave/client_enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --use-prefix --trusted ../Enclave/client_enclave.edl --search-path $(SGX_SDK)/include 
	@echo "GEN  =>  $@"

Enclave/client_enclave_t.c: Enclave/client_enclave_t.h

Enclave/client_enclave_t.o: Enclave/client_enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp Enclave/client_enclave_t.h
	@$(CXX) $(Enclave_Cxx_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

Enclave.so: Enclave/client_enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) Enclave/client_enclave_t.o $(Enclave_Cpp_Objects) -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Enclave_Name): Enclave.so
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private.pem -enclave Enclave.so -out $@ -config Enclave/Enclave.config.xml
	@echo "SIGN =>  $@"

######## Clean ########
.PHONY: clean

clean:
	@rm -rf .config_* $(App_Name) *.so *.a App/*.o Enclave/*.o Enclave/*_t.* Enclave/*_u.*
