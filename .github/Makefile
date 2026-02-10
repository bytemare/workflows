.PHONY: release
release:
	@echo "Creating a new release ..."\
	@tag=$${tag:-};\
	 if [ -z "$$tag" ]; then\
	 	 echo "Error: tag variable is not set. Use 'make release tag=vX.Y.Z'";\
	 	 exit 1;\
	 fi;\
	 git fetch origin;\
	if ! git tag -s -a "$$tag" -m "chore: cut $$tag"; then\
		echo "Error: Failed to create tag";\
		exit 1;\
	fi;\
	git push origin "$$tag"
