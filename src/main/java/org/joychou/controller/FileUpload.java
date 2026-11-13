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
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
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
    private static final int MAX_FILE_NAME_LENGTH = 100;
    private static String randomFilePath = "";

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

        String safeName = safeFileName(file.getOriginalFilename());
        Path path = safeName == null ? null : resolveUploadPath(safeName);
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

        String fileName = safeFileName(multifile.getOriginalFilename());
        Path targetPath = fileName == null ? null : resolveUploadPath(fileName);
        if (targetPath == null) {
            logger.error("[-] Illegal file name");
            return "Upload failed. Illeagl picture.";
        }
        String Suffix = fileName.substring(fileName.lastIndexOf(".")); // 获取文件后缀名
        String mimeType = multifile.getContentType(); // 获取MIME类型
        String filePath = UPLOADED_FOLDER + fileName;
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
            logger.error("[-] Suffix error: {}", SecurityUtil.logSafe(Suffix));
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
                logger.error("[-] Mime type error: {}", SecurityUtil.logSafe(mimeType));
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
            Files.write(targetPath, bytes);
        } catch (IOException e) {
            logger.error(e.toString());
            deleteFile(filePath);
            return "Upload failed";
        }

        logger.info("[+] Safe file. Suffix: {}, MIME: {}", SecurityUtil.logSafe(Suffix), SecurityUtil.logSafe(mimeType));
        logger.info("[+] Successfully uploaded {}", SecurityUtil.logSafe(filePath));
        return String.format("You successfully uploaded '%s'", HtmlUtils.htmlEscape(filePath));
    }

    /**
     * Reduce a client supplied file name to its last path segment.
     *
     * @return null if the name is empty or cannot be a plain file name
     */
    private static String safeFileName(String original) {
        if (original == null) {
            return null;
        }
        String name = original.replace('\\', '/');
        name = name.substring(name.lastIndexOf('/') + 1);
        if (name.isEmpty() || name.indexOf('\0') >= 0 || name.matches("\\.+")) {
            return null;
        }
        // Restrict to a safe character set and bound the length (keep the tail so the suffix survives).
        name = name.replaceAll("[^A-Za-z0-9._-]", "_");
        if (name.length() > MAX_FILE_NAME_LENGTH) {
            name = name.substring(name.length() - MAX_FILE_NAME_LENGTH);
        }
        return name;
    }

    /**
     * Resolve an untrusted file name to a path that is a direct child of the fixed
     * server-side UPLOADED_FOLDER. Every file sink in this class must use only the
     * Path returned here.
     *
     * @return null if the name is unusable or the result would not be inside UPLOADED_FOLDER
     */
    private static Path resolveUploadPath(String untrustedName) {
        String name = safeFileName(untrustedName);
        if (name == null) {
            return null;
        }
        Path base;
        Path resolved;
        try {
            base = Paths.get(UPLOADED_FOLDER).toRealPath();
            resolved = base.resolve(name).normalize();
        } catch (InvalidPathException | IOException e) {
            return null;
        }
        if (!resolved.startsWith(base) || !base.equals(resolved.getParent())) {
            return null;
        }
        return resolved;
    }

    private void deleteFile(String filePath) {
        Path base = Paths.get(UPLOADED_FOLDER).toAbsolutePath().normalize();
        Path delPath = Paths.get(filePath).toAbsolutePath().normalize();
        if (!delPath.startsWith(base)) {
            logger.info("{} delete failed!", SecurityUtil.logSafe(filePath));
            return;
        }
        File delFile = delPath.toFile();
        if(delFile.isFile() && delFile.exists()) {
            if (delFile.delete()) {
                logger.info("[+] {} delete successfully!", SecurityUtil.logSafe(filePath));
                return;
            }
        }
        logger.info("{} delete failed!", SecurityUtil.logSafe(filePath));
    }

    /**
     * 为了使用ImageIO.read()
     *
     * 不建议使用transferTo，因为原始的MultipartFile会被覆盖
     * https://stackoverflow.com/questions/24339990/how-to-convert-a-multipart-file-to-file
     */
    private File convert(MultipartFile multiFile) throws Exception {
        String fileName = safeFileName(multiFile.getOriginalFilename());
        if (fileName == null) {
            throw new IOException("Illegal file name");
        }
        String suffix = fileName.substring(fileName.lastIndexOf("."));
        UUID uuid = Generators.timeBasedGenerator().generate();
        Path convPath = resolveUploadPath(uuid + suffix);
        if (convPath == null) {
            throw new IOException("Illegal file name");
        }
        randomFilePath = convPath.toString();
        // 随机生成一个同后缀名的文件
        File convFile = convPath.toFile();
        boolean ret = convFile.createNewFile();
        if (!ret) {
            return null;
        }
        Files.write(convPath, multiFile.getBytes());
        return convFile;
    }

    /**
     * Check if the file is a picture.
     */
    private static boolean isImage(File file) throws IOException {
        BufferedImage bi = ImageIO.read(file);
        return bi != null;
    }
}
