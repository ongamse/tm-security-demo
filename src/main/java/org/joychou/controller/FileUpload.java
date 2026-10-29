package org.joychou.controller;

import com.fasterxml.uuid.Generators;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.util.HtmlUtils;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.UUID;

import org.joychou.security.SecurityUtil;


/**
 * File upload.
 *
 * @author JoyChou @ 2018-08-15
 */
@Controller
@RequestMapping("/file")
public class FileUpload {

    // Save the uploaded file to this folder
    private static final String UPLOADED_FOLDER = "/tmp/";
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private static Path randomFilePath = null;

    // Allowlisted extensions; stored names only ever use these constants.
    private static final String[] PIC_SUFFIX_LIST = {".jpg", ".png", ".jpeg", ".gif", ".bmp", ".ico"};
    private static final String[] ANY_SUFFIX_LIST = {".jpg", ".png", ".jpeg", ".gif", ".bmp", ".ico",
            ".txt", ".pdf", ".csv", ".zip", ".doc", ".docx", ".xls", ".xlsx"};

    // uplaod any file
    @GetMapping("/any")
    public String index() {
        return "upload"; // return upload.html page
    }

    // only allow to upload pictures
    @GetMapping("/pic")
    public String uploadPic() {
        return "uploadPic"; // return uploadPic.html page
    }

    @PostMapping("/upload")
    public String singleFileUpload(@RequestParam("file") MultipartFile file,
                                   RedirectAttributes redirectAttributes) {
        if (file.isEmpty()) {
            // 赋值给uploadStatus.html里的动态参数message
            redirectAttributes.addFlashAttribute("message", "Please select a file to upload");
            return "redirect:/file/status";
        }

        // The stored name is generated server-side; only an allowlisted extension
        // constant (never the client supplied string) is used as part of the path.
        String ext = allowedExtension(file.getOriginalFilename(), ANY_SUFFIX_LIST);
        Path path = newUploadPath(ext == null ? "" : ext);
        if (path == null) {
            redirectAttributes.addFlashAttribute("message", "Illegal file name");
            return "redirect:/file/status";
        }

        try {
            // Get the file and save it somewhere
            byte[] bytes = file.getBytes();
            Files.write(path, bytes);

            redirectAttributes.addFlashAttribute("message",
                    "You successfully uploaded '" + path + "'");

        } catch (IOException e) {
            redirectAttributes.addFlashAttribute("message", "upload failed");
            logger.error(e.toString());
        }

        return "redirect:/file/status";
    }

    @GetMapping("/status")
    public String uploadStatus() {
        return "uploadStatus";
    }

    // only upload picture
    @PostMapping("/upload/picture")
    @ResponseBody
    public String uploadPicture(@RequestParam("file") MultipartFile multifile) throws Exception {
        if (multifile.isEmpty()) {
            return "Please select a file to upload";
        }

        // 判断文件后缀名是否在白名单内  校验1
        // Suffix is always one of the constants in PIC_SUFFIX_LIST (or null)
        String Suffix = allowedExtension(multifile.getOriginalFilename(), PIC_SUFFIX_LIST);
        if (Suffix == null) {
            logger.error("[-] Suffix error");
            return "Upload failed. Illeagl picture.";
        }

        Path safePath = newUploadPath(Suffix);
        if (safePath == null) {
            logger.error("[-] Illegal file name");
            return "Upload failed. Illeagl picture.";
        }
        String mimeType = multifile.getContentType(); // 获取MIME类型
        String filePath = safePath.toString();
        File excelFile = convert(multifile, Suffix);


        // 判断MIME类型是否在黑名单内 校验2
        String[] mimeTypeBlackList = {
                "text/html",
                "text/javascript",
                "application/javascript",
                "application/ecmascript",
                "text/xml",
                "application/xml"
        };
        for (String blackMimeType : mimeTypeBlackList) {
            // 用contains是为了防止text/html;charset=UTF-8绕过
            if (SecurityUtil.replaceSpecialStr(mimeType).toLowerCase().contains(blackMimeType)) {
                logger.error("[-] Mime type error: " + mimeType);
                deleteFile(randomFilePath);
                return "Upload failed. Illeagl picture.";
            }
        }

        // 判断文件内容是否是图片 校验3
        boolean isImageFlag = excelFile != null && isImage(excelFile);
        deleteFile(randomFilePath);

        if (!isImageFlag) {
            logger.error("[-] File is not Image");
            return "Upload failed. Illeagl picture.";
        }


        try {
            // Get the file and save it somewhere
            byte[] bytes = multifile.getBytes();
            Files.write(safePath, bytes);
        } catch (IOException e) {
            logger.error(e.toString());
            deleteFile(safePath);
            return "Upload failed";
        }

        logger.info("[+] Safe file. Suffix: {}, MIME: {}", Suffix, mimeType);
        logger.info("[+] Successfully uploaded {}", filePath);
        return String.format("You successfully uploaded '%s'", HtmlUtils.htmlEscape(filePath));
    }

    /**
     * Return the allowlisted extension constant matching the client supplied file name,
     * or null. The returned value is always an element of {@code allowed}, never a
     * substring of the client supplied name.
     */
    private static String allowedExtension(String originalFilename, String[] allowed) {
        if (originalFilename == null) {
            return null;
        }
        String lower = originalFilename.toLowerCase(java.util.Locale.ROOT);
        for (String ext : allowed) {
            if (lower.endsWith(ext) && lower.length() > ext.length()) {
                return ext;
            }
        }
        return null;
    }

    /**
     * Build a new server-generated path inside UPLOADED_FOLDER: random UUID plus a
     * constant allowlisted extension. No client supplied string is part of the path.
     *
     * @return safe path, or null if it would escape UPLOADED_FOLDER
     */
    private static Path newUploadPath(String allowlistedExt) {
        Path base = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        Path target = base.resolve(UUID.randomUUID() + allowlistedExt).normalize();
        if (!target.startsWith(base) || !base.equals(target.getParent())) {
            return null;
        }
        return target;
    }

    private void deleteFile(Path filePath) {
        if (filePath == null) {
            return;
        }
        try {
            if (Files.deleteIfExists(filePath)) {
                logger.info("[+] " + filePath + " delete successfully!");
                return;
            }
        } catch (IOException e) {
            logger.error(e.toString());
        }
        logger.info(filePath + " delete failed!");
    }

    /**
     * 为了使用ImageIO.read()
     *
     * 不建议使用transferTo，因为原始的MultipartFile会被覆盖
     * https://stackoverflow.com/questions/24339990/how-to-convert-a-multipart-file-to-file
     */
    private File convert(MultipartFile multiFile, String allowlistedSuffix) throws Exception {
        UUID uuid = Generators.timeBasedGenerator().generate();
        // 随机生成一个同后缀名的文件
        Path convPath = newUploadPath("conv-" + uuid + allowlistedSuffix);
        if (convPath == null) {
            return null;
        }
        randomFilePath = convPath;
        try {
            Files.write(convPath, multiFile.getBytes(), StandardOpenOption.CREATE_NEW);
        } catch (FileAlreadyExistsException e) {
            return null;
        }
        return convPath.toFile();
    }

    /**
     * Check if the file is a picture.
     */
    private static boolean isImage(File file) throws IOException {
        BufferedImage bi = ImageIO.read(file);
        return bi != null;
    }
}
