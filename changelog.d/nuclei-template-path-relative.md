### Fixed: nuclei findings report the template's place in its pack, not a path on the sensor
- The template file nuclei prints (a path under the sensor's content directory) is replaced in the report by `<pack>/versions/<release>/<file>`, or the file relative to the templates directory; an unusable path is dropped.
