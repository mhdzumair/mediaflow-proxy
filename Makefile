# Makefile

# Variables to hold version tags and contributor names
VERSION_OLD ?=
VERSION_NEW ?=
CONTRIBUTORS ?= $(shell git log --pretty=format:'%an' $(VERSION_OLD)..$(VERSION_NEW) | sort | uniq)
GITHUB_RELEASE_BODY_FILE ?=

# Gemini API settings
GEMINI_MODEL ?= gemini-3-flash-preview
MAX_TOKENS ?= 8000

.PHONY: generate-notes prompt all

prompt:
ifndef VERSION_OLD
	@echo "Error: VERSION_OLD is not set. Please set it like: make prompt VERSION_OLD=x.x.x VERSION_NEW=y.y.y CONTRIBUTORS='@user1, @user2'"
	@exit 1
endif
ifndef VERSION_NEW
	@echo "Error: VERSION_NEW is not set. Please set it like: make prompt VERSION_OLD=x.x.x VERSION_NEW=y.y.y CONTRIBUTORS='@user1, @user2'"
	@exit 1
endif
	@echo "Generate a release note for MediaFlow $(VERSION_NEW) by analyzing the following changes. Organize the release note by importance rather than by commit order. highlight the most significant updates first, and streamline the content to focus on what adds the most value to the user. Ensure to dynamically create sections for New Features & Enhancements, Bug Fixes, and Documentation updates only if relevant based on the types of changes listed. Use emojis relevantly at the start of each item to enhance readability and engagement. Keep the format straightforward & shorter, provide a direct link to the detailed list of changes:\n"
	@echo "When available, use contributor usernames from the GitHub-generated release notes reference and preserve @username mentions in the final Contributors section.\n"
	@echo "## 🚀 MediaFlow $(VERSION_NEW) Released\n"
	@echo "### Commit Messages and Descriptions:\n"
	@git log --pretty=format:'%s%n%b' $(VERSION_OLD)..$(VERSION_NEW) | awk 'BEGIN {RS="\n\n"; FS="\n"} { \
		message = $$1; \
		description = ""; \
		for (i=2; i<=NF; i++) { \
			if ($$i ~ /^\*/) description = description "  " $$i "\n"; \
			else if ($$i != "") description = description "  " $$i "\n"; \
		} \
		if (message != "") print "- " message; \
		if (description != "") printf "%s", description; \
	}'
	@echo "--- \n### 🤝 Contributors (if GitHub usernames are available in the reference, use @username format; otherwise fallback to these names): $(CONTRIBUTORS)\n\n### 📄 Full Changelog:\nhttps://github.com/mhdzumair/mediaflow-proxy/compare/$(VERSION_OLD)...$(VERSION_NEW)";
ifneq ($(strip $(GITHUB_RELEASE_BODY_FILE)),)
	@if [ -f "$(GITHUB_RELEASE_BODY_FILE)" ]; then \
		echo "\n--- \n### GitHub-generated release notes reference (for contributor usernames):\n"; \
		cat "$(GITHUB_RELEASE_BODY_FILE)"; \
	fi
endif


generate-notes:
ifndef VERSION_OLD
	@echo "Error: VERSION_OLD is not set"
	@exit 1
endif
ifndef VERSION_NEW
	@echo "Error: VERSION_NEW is not set"
	@exit 1
endif
ifndef GEMINI_API_KEY
	@echo "Error: GEMINI_API_KEY is not set"
	@exit 1
endif
	@PROMPT_CONTENT=$$(make prompt VERSION_OLD=$(VERSION_OLD) VERSION_NEW=$(VERSION_NEW) | jq -sRr @json); \
	if [ -z "$$PROMPT_CONTENT" ]; then \
	    echo "Failed to generate release notes using Gemini AI, prompt content is empty"; \
	    exit 1; \
	fi; \
	temp_file=$$(mktemp); \
	curl -s "https://generativelanguage.googleapis.com/v1beta/models/$(GEMINI_MODEL):generateContent" \
		--header "x-goog-api-key: $(GEMINI_API_KEY)" \
		--header "content-type: application/json" \
		--data "{\"contents\":[{\"parts\":[{\"text\":$$PROMPT_CONTENT}]}],\"generationConfig\":{\"maxOutputTokens\":$(MAX_TOKENS)}}" > $$temp_file; \
	RESULT=$$(jq -r '[.candidates[0].content.parts[] | select(.thought != true) | .text] | join("")' $$temp_file 2>/dev/null); \
	if [ -z "$$RESULT" ] || [ "$$RESULT" = "null" ]; then \
	    echo "Failed to generate release notes using Gemini AI, response: $$(cat $$temp_file)"; rm $$temp_file; exit 1; \
	fi; \
	echo "$$RESULT"; \
	rm $$temp_file

all: generate-notes