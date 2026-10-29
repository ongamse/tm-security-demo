package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import com.fasterxml.uuid.Generators;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Locale;
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

        String safeName = sanitizeFileName(file.getOriginalFilename());
        Path path = resolveInUploadFolder(safeName);
        if (path == null) {
            redirectAttributes.addFlashAttribute("message", "Illegal file name");
            return "redirect:/file/status";
        }

        try {
            // Get the file and save it somewhere
            byte[] bytes = file.getBytes();
            Files.write(path, bytes);

            redirectAttributes.addFlashAttribute("message",
                    "You successfully uploaded '" + UPLOADED_FOLDER + safeName + "'");

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

        String fileName = sanitizeFileName(multifile.getOriginalFilename());
        Path savePath = resolveInUploadFolder(fileName);
        if (savePath == null) {
            logger.error("[-] Illegal file name");
            return "Upload failed. Illeagl picture.";
        }
        String mimeType = multifile.getContentType(); // 获取MIME类型
        String filePath = UPLOADED_FOLDER + fileName;

        // 判断文件后缀名是否在白名单内  校验1
        // The suffix is a server-side constant chosen from the allowlist, never a substring of the request name.
        String suffix = allowedImageSuffix(fileName);
        if (suffix == null) {
            logger.error("[-] Suffix error");
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
                logger.error("[-] Mime type error: " + mimeType);
                return "Upload failed. Illeagl picture.";
            }
        }

        // 判断文件内容是否是图片 校验3
        // The temporary copy has a fully server-generated name and is always removed.
        File tempFile = null;
        boolean isImageFlag;
        try {
            tempFile = convert(multifile, suffix);
            isImageFlag = isImage(tempFile);
        } finally {
            deleteQuietly(tempFile);
        }

        if (!isImageFlag) {
            logger.error("[-] File is not Image");
            return "Upload failed. Illeagl picture.";
        }


        try {
            // Get the file and save it somewhere
            byte[] bytes = multifile.getBytes();
            Files.write(savePath, bytes);
        } catch (IOException e) {
            logger.error(e.toString());
            return "Upload failed";
        }

        logger.info("[+] Safe file. Suffix: {}, MIME: {}", suffix, mimeType);
        logger.info("[+] Successfully uploaded {}", filePath);
        return String.format("You successfully uploaded '%s'", HtmlUtils.htmlEscape(filePath));
    }

    /**
     * Reduce a client supplied file name to a bare file name (no directory components).
     *
     * @return the bare file name, or null if it is not acceptable
     */
    private static String sanitizeFileName(String originalName) {
        if (originalName == null || originalName.indexOf('\0') != -1) {
            return null;
        }
        String name = originalName.replace('\\', '/');
        name = name.substring(name.lastIndexOf('/') + 1);
        if (name.isEmpty() || name.equals(".") || name.equals("..")) {
            return null;
        }
        return name;
    }

    /**
     * Resolve a bare file name inside the upload folder and make sure it does not escape it.
     *
     * @return the normalized absolute path, or null if the name is invalid or escapes the folder
     */
    private static Path resolveInUploadFolder(String safeName) {
        if (safeName == null) {
            return null;
        }
        Path base = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        Path target = base.resolve(safeName).normalize();
        if (!target.startsWith(base) || !base.equals(target.getParent())) {
            return null;
        }
        return target;
    }

    /**
     * Map a file name to an allowlisted image suffix. The returned value is always one of the
     * constant literals below, never a substring of the (request supplied) name.
     *
     * @return the constant suffix, or null if the name does not end with an allowed one
     */
    private static String allowedImageSuffix(String fileName) {
        if (fileName == null) {
            return null;
        }
        int dot = fileName.lastIndexOf('.');
        if (dot < 0) {
            return null;
        }
        switch (fileName.substring(dot).toLowerCase(Locale.ROOT)) {
            case ".jpg":
                return ".jpg";
            case ".jpeg":
                return ".jpeg";
            case ".png":
                return ".png";
            case ".gif":
                return ".gif";
            case ".bmp":
                return ".bmp";
            case ".ico":
                return ".ico";
            default:
                return null;
        }
    }

    /**
     * Delete a server-generated temporary file. Failures are logged, never thrown.
     */
    private void deleteQuietly(File file) {
        if (file == null) {
            return;
        }
        try {
            if (Files.deleteIfExists(file.toPath())) {
                logger.info("[+] temporary file delete successfully!");
            }
        } catch (IOException e) {
            logger.info("temporary file delete failed: {}", e.toString());
        }
    }

    /**
     * 为了使用ImageIO.read()
     *
     * 不建议使用transferTo，因为原始的MultipartFile会被覆盖
     * https://stackoverflow.com/questions/24339990/how-to-convert-a-multipart-file-to-file
     *
     * The file name is fully server generated: UUID + an allowlisted constant suffix.
     */
    private File convert(MultipartFile multiFile, String allowedSuffix) throws Exception {
        UUID uuid = Generators.timeBasedGenerator().generate();
        // 随机生成一个同后缀名的文件
        Path convPath = resolveInUploadFolder(uuid + allowedSuffix);
        if (convPath == null) {
            throw new IllegalArgumentException("Illegal file name");
        }
        Files.write(convPath, multiFile.getBytes(), StandardOpenOption.CREATE_NEW);
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
