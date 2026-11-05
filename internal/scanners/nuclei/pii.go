package nuclei

// Personal data is never collected (openctem research/292: e-mail addresses
// and other personal data of the people behind a target are not stored).
// Some templates of the nuclei-templates release exist only to harvest
// personal data from a target's responses: they report no weakness, their
// result is the data itself, which would land in a finding's title,
// evidence and extracted results. They never run, whatever a scan selects.
//
// Measured on nuclei v3.11.1 with nuclei-templates v10.4.9: -exclude-id drops
// a template however it was selected (-id naming it, -t naming its file, a
// -tags selection, a global matcher), so the list is passed on every run.
//
// Templates that report a vulnerability and show personal data as proof (a
// user listing exposed by a plugin flaw) still run: the platform masks
// e-mail addresses in every finding it stores.

// PIIExcludedTemplateIDs are the template ids a scan never runs, with what
// each one harvests (nuclei-templates v10.4.9 and v10.5.1):
//   - email-extractor: every e-mail address in a page body.
//   - secrets-patterns-pii: a global matcher extracting e-mail addresses and
//     phone numbers from every response of the run.
//   - rdap-whois: a domain registrant's name, e-mail, phone and postal address.
//   - credit-card-number-detect: payment card numbers in a page body.
var PIIExcludedTemplateIDs = []string{
	"email-extractor",
	"secrets-patterns-pii",
	"rdap-whois",
	"credit-card-number-detect",
}

// excludedIDs is the -exclude-id list of a run: PIIExcludedTemplateIDs,
// then the scanner's own exclusions, without duplicates or blanks.
func (s *Scanner) excludedIDs() []string {
	return mergeTags(PIIExcludedTemplateIDs, s.ExcludeIDs)
}
