package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;

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
    private static String randomFilePath = "";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

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

        try {
            // Get the file and save it somewhere
            byte[] bytes = file.getBytes();
            String safeName = sanitizeFileName(file.getOriginalFilename());
            if (safeName == null) {
                redirectAttributes.addFlashAttribute("message", "Illegal file name");
                return "redirect:/file/status";
            }
            Path path = resolveUploadPath(safeName);
            Files.write(path, bytes);

            redirectAttributes.addFlashAttribute("message",
                    "You successfully uploaded '" + UPLOADED_FOLDER + safeName + "'");

        } catch (IOException e) {
            redirectAttributes.addFlashAttribute("message", "upload failed");
            logger.error("File upload processing failed", e);
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

        // Strip any directory components so the name cannot escape UPLOADED_FOLDER
        String fileName = sanitizeFileName(multifile.getOriginalFilename());
        if (fileName == null) {
            logger.error("[-] Illegal file name");
            return "Upload failed. Illeagl picture.";
        }
        String Suffix = fileName.substring(fileName.lastIndexOf(".")); // 获取文件后缀名
        String mimeType = multifile.getContentType(); // 获取MIME类型
        String filePath = resolveUploadPath(fileName).toString();
        File excelFile = convert(multifile);


        // 判断文件后缀名是否在白名单内  校验1
        String[] picSuffixList = {".jpg", ".png", ".jpeg", ".gif", ".bmp", ".ico"};
        boolean suffixFlag = false;
        for (String white_suffix : picSuffixList) {
            if (Suffix.toLowerCase().equals(white_suffix)) {
                suffixFlag = true;
                break;
            }
        }
        if (!suffixFlag) {
            logger.error("[-] Suffix error");
            deleteFile(filePath);
            return "Upload failed. Illeagl picture.";
        }


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
                logger.error("[-] Mime type error");
                deleteFile(filePath);
                return "Upload failed. Illeagl picture.";
            }
        }

        // 判断文件内容是否是图片 校验3
        boolean isImageFlag = isImage(excelFile);
        deleteFile(randomFilePath);

        if (!isImageFlag) {
            logger.error("[-] File is not Image");
            deleteFile(filePath);
            return "Upload failed. Illeagl picture.";
        }


        try {
            // Get the file and save it somewhere
            byte[] bytes = multifile.getBytes();
            Path path = resolveUploadPath(fileName);
            Files.write(path, bytes);
        } catch (IOException e) {
            logger.error("File upload processing failed", e);
            deleteFile(filePath);
            return "Upload failed";
        }

        logger.info("[+] Safe file");
        logger.info("[+] Successfully uploaded");
        return String.format("You successfully uploaded '%s'", HtmlUtils.htmlEscape(filePath));
    }

    /**
     * Reduce a client supplied file name to its last path component.
     *
     * @return the bare file name, or null if it is empty / not usable
     */
    private static String sanitizeFileName(String originalName) {
        if (originalName == null) {
            return null;
        }
        String name = originalName.replace('\\', '/');
        name = name.substring(name.lastIndexOf('/') + 1);
        if (name.isEmpty() || name.equals(".") || name.equals("..") || name.indexOf('\0') >= 0) {
            return null;
        }
        return name;
    }

    /**
     * Resolve a bare file name inside UPLOADED_FOLDER and make sure the
     * normalized result cannot escape that folder.
     */
    private static Path resolveUploadPath(String safeName) throws IOException {
        Path base = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        Path resolved = base.resolve(safeName).normalize();
        if (!resolved.startsWith(base) || resolved.equals(base)) {
            throw new IOException("Illegal file path");
        }
        return resolved;
    }

    private void deleteFile(String filePath) {
        Path base = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        Path target = Paths.get(filePath).toAbsolutePath().normalize();
        if (!target.startsWith(base) || target.equals(base)) {
            logger.info("[-] Refusing to delete path outside upload folder");
            return;
        }
        try {
            // Single atomic operation instead of isFile()/exists() followed by delete().
            if (Files.deleteIfExists(target)) {
                logger.info("[+] Uploaded file deleted successfully");
            }
        } catch (IOException e) {
            logger.info("Uploaded file delete failed", e);
        }
    }

    /**
     * 为了使用ImageIO.read()
     *
     * 不建议使用transferTo，因为原始的MultipartFile会被覆盖
     * https://stackoverflow.com/questions/24339990/how-to-convert-a-multipart-file-to-file
     */
    private File convert(MultipartFile multiFile) throws Exception {
        String fileName = sanitizeFileName(multiFile.getOriginalFilename());
        if (fileName == null) {
            throw new IOException("Illegal file name");
        }
        String suffix = fileName.substring(fileName.lastIndexOf("."));
        // 随机生成一个同后缀名的文件 (unpredictable name, atomic owner-only create)
        Path randomPath = null;
        for (int attempt = 0; attempt < 2 && randomPath == null; attempt++) {
            Path candidate = resolveUploadPath(secureRandomName() + suffix);
            try {
                randomPath = createOwnerOnlyFile(candidate);
            } catch (FileAlreadyExistsException e) {
                logger.info("[-] Random file name collision, retrying");
            }
        }
        if (randomPath == null) {
            return null;
        }
        randomFilePath = randomPath.toString();
        Files.write(randomPath, multiFile.getBytes());
        return randomPath.toFile();
    }

    /**
     * 128 bits from SecureRandom rendered as lowercase hex.
     */
    private static String secureRandomName() {
        byte[] raw = new byte[16];
        SECURE_RANDOM.nextBytes(raw);
        char[] out = new char[raw.length * 2];
        for (int i = 0; i < raw.length; i++) {
            int v = raw[i] & 0xFF;
            out[i * 2] = HEX_CHARS[v >>> 4];
            out[i * 2 + 1] = HEX_CHARS[v & 0x0F];
        }
        return new String(out);
    }

    /**
     * Atomically create a new file (fails if it exists), owner read/write only
     * where the filesystem supports POSIX permissions.
     */
    private static Path createOwnerOnlyFile(Path path) throws IOException {
        try {
            return Files.createFile(path,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } catch (UnsupportedOperationException e) {
            return Files.createFile(path);
        }
    }

    /**
     * Check if the file is a picture.
     */
    private static boolean isImage(File file) throws IOException {
        BufferedImage bi = ImageIO.read(file);
        return bi != null;
    }
}
