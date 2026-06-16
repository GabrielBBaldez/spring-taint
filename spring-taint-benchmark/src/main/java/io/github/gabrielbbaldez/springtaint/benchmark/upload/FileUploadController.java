package io.github.gabrielbbaldez.springtaint.benchmark.upload;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;

/**
 * Path traversal via an uploaded file's name. {@code getOriginalFilename()} is
 * fully attacker-controlled (e.g. {@code ../../etc/cron.d/evil}); concatenating it
 * into a path escapes the upload directory. File upload is a frequently-ignored
 * source.
 *
 * <p>EXPECTED: path-traversal (CWE-22). Source: MultipartFile.getOriginalFilename().
 */
@RestController
public class FileUploadController {

    @PostMapping("/upload")
    public String upload(@RequestParam MultipartFile file) {
        String filename = file.getOriginalFilename();   // taint-source: MultipartFile.getOriginalFilename()
        File dest = new File("/uploads/" + filename);    // taint-sink: new File(String) -> EXPECTED path-traversal
        return dest.getAbsolutePath();
    }
}
