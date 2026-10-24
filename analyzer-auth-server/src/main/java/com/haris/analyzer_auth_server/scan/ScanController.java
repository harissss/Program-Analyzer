package com.haris.analyzer_auth_server.scan;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;

@RestController
@RequestMapping("/api")
public class ScanController {
    private final long MAX_SIZE = 0x4000000; //1MB
    private final int BUFFER_SIZE = 512;

    @RequestMapping(path="/scan", method=RequestMethod.POST, consumes=MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> scanZip(@RequestPart("file") MultipartFile zipFolder) {
        if (zipFolder.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("zip folder is not given or empty.");
        }

        //if (zipFolder.getContentType().equals("zip")) TODO: should check this somehow?

        if (zipFolder.getSize() > MAX_SIZE) {
            return ResponseEntity.status(HttpStatus.CONTENT_TOO_LARGE)
                    .body("zip folder is too large (max 1MB allowed).");
        }

        try (InputStream inStream = new BufferedInputStream(zipFolder.getInputStream()); //try-with-resources auto-closes them
            OutputStream outStream = new BufferedOutputStream(
                    new FileOutputStream("tmp/code-uploads/test.zip")
            )) {
            //ZipInputStream zipInStream = new ZipInputStream(inStream); this is used to extract
            int readData;
            byte[] data = new byte[BUFFER_SIZE];

            while ((readData = inStream.read(data, 0, BUFFER_SIZE)) != -1) {
                outStream.write(data, 0, readData);
            }
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to get file contents.");
        }

        return ResponseEntity.status(HttpStatus.OK)
                .body("Successfully did something.");
    }

    /*@RequestMapping(path="/scans/{id}", method=RequestMethod.GET)
    public ResponseEntity<String> getScanWithId(@RequestBody ScansIdRequest request) {
        return ResponseEntity.status(HttpStatus.OK).body("hello");
    }

    @RequestMapping(path="/scans/{id}/findings", method=RequestMethod.GET)
    public ResponseEntity<String> getScanFindings(@RequestBody ScansFindingsRequest request) {
        return ResponseEntity.status(HttpStatus.OK).body("hello");
    }*/
}
