### Fixed: the passive image holds no compiled-in tool above T0

- v0.38.3 put the compiled-in path discovery tool (`webguess`, T1) in the passive image, which broke its guarantee of no program that can touch a target; its image build failed the smoke test, so v0.38.3 has no images. The passive image is now built with the passive profile (`internal/imageprofile`, set by the linker): a compiled-in tool above T0 is not registered, listed or detected in that binary. Use v0.38.4 or later. The smoke test stays the proof.
